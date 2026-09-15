package tor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortRange struct {
	Start int
	End   int
}

func (r PortRange) validate(name string) error {
	if r.Start < 1 || r.End > 65535 || r.Start > r.End {
		return fmt.Errorf("invalid %s port range %d-%d", name, r.Start, r.End)
	}
	return nil
}

type ManagerConfig struct {
	ExecutablePath       string
	DataRoot             string
	XrayPorts            PortRange
	SocksPorts           PortRange
	ControlPorts         PortRange
	HealthCheckInterval  time.Duration
	StartupTimeout       time.Duration
	OperationTimeout     time.Duration
	NewIdentityWait      time.Duration
	MaxRestartAttempts   int
	RestartBackoff       []time.Duration
	StartupConcurrency   int
	CountryVerification  bool
	AutoRepair           bool
}

func (c *ManagerConfig) normalize() error {
	if strings.TrimSpace(c.ExecutablePath) == "" {
		c.ExecutablePath = "/usr/bin/tor"
	}
	if strings.TrimSpace(c.DataRoot) == "" {
		c.DataRoot = "/var/lib/bluepanel-node/tor"
	}
	if c.XrayPorts.Start == 0 && c.XrayPorts.End == 0 {
		c.XrayPorts = PortRange{Start: 31000, End: 31999}
	}
	if c.SocksPorts.Start == 0 && c.SocksPorts.End == 0 {
		c.SocksPorts = PortRange{Start: 19000, End: 19999}
	}
	if c.ControlPorts.Start == 0 && c.ControlPorts.End == 0 {
		c.ControlPorts = PortRange{Start: 20000, End: 20999}
	}
	if err := c.XrayPorts.validate("Xray"); err != nil { return err }
	if err := c.SocksPorts.validate("SOCKS"); err != nil { return err }
	if err := c.ControlPorts.validate("Control"); err != nil { return err }
	if c.HealthCheckInterval <= 0 { c.HealthCheckInterval = 60 * time.Second }
	if c.StartupTimeout <= 0 { c.StartupTimeout = 45 * time.Second }
	if c.OperationTimeout <= 0 { c.OperationTimeout = 15 * time.Second }
	if c.NewIdentityWait <= 0 { c.NewIdentityWait = 5 * time.Second }
	if c.MaxRestartAttempts <= 0 { c.MaxRestartAttempts = 5 }
	if len(c.RestartBackoff) == 0 {
		c.RestartBackoff = []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 30 * time.Minute}
	}
	if c.StartupConcurrency <= 0 { c.StartupConcurrency = 3 }
	return nil
}

type instance struct {
	mu      sync.Mutex
	loc     *Location
	cmd     *exec.Cmd
	logFile *os.File
	done    chan error
}

type Manager struct {
	cfg      ManagerConfig
	verifier ExitVerifier

	mu        sync.RWMutex
	instances map[string]*instance
	xray      XrayAdapter

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewManager(cfg ManagerConfig, verifier ExitVerifier) (*Manager, error) {
	if err := cfg.normalize(); err != nil { return nil, err }
	if verifier == nil { verifier = NewHTTPExitVerifier(cfg.OperationTimeout) }
	if err := os.MkdirAll(filepath.Join(cfg.DataRoot, "instances"), 0o700); err != nil {
		return nil, fmt.Errorf("create Tor data root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.DataRoot, "retained"), 0o700); err != nil {
		return nil, fmt.Errorf("create Tor retained root: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{cfg: cfg, verifier: verifier, instances: make(map[string]*instance), ctx: ctx, cancel: cancel}
	if err := m.loadState(); err != nil {
		cancel()
		return nil, err
	}
	m.wg.Add(1)
	go m.healthLoop()
	return m, nil
}

func (m *Manager) Close() {
	m.cancel()
	m.wg.Wait()
	m.mu.RLock()
	instances := make([]*instance, 0, len(m.instances))
	for _, inst := range m.instances { instances = append(instances, inst) }
	m.mu.RUnlock()
	for _, inst := range instances { _ = m.stopInstance(inst) }
}

func (m *Manager) AttachXray(adapter XrayAdapter) {
	m.mu.Lock()
	m.xray = adapter
	m.mu.Unlock()
}

func (m *Manager) DetachXray() {
	m.mu.Lock()
	m.xray = nil
	m.mu.Unlock()
}

func (m *Manager) xrayAdapter() XrayAdapter {
	m.mu.RLock(); defer m.mu.RUnlock(); return m.xray
}

func (m *Manager) locationDir(id, slug string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(m.cfg.DataRoot, "instances", hex.EncodeToString(sum[:8])+"-"+slug)
}

func (m *Manager) statePath(loc *Location) string { return filepath.Join(loc.TorDataDirectory, "bluepanel-location.json") }
func (m *Manager) torrcPath(loc *Location) string { return filepath.Join(loc.TorDataDirectory, "torrc") }

func (m *Manager) persist(loc *Location) error {
	loc.UpdatedAt = time.Now().UTC()
	if err := os.MkdirAll(loc.TorDataDirectory, 0o700); err != nil { return err }
	data, err := json.MarshalIndent(loc, "", "  ")
	if err != nil { return err }
	tmp := m.statePath(loc) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil { return err }
	return os.Rename(tmp, m.statePath(loc))
}

func (m *Manager) loadState() error {
	root := filepath.Join(m.cfg.DataRoot, "instances")
	entries, err := os.ReadDir(root)
	if err != nil { return fmt.Errorf("read Tor state root: %w", err) }
	for _, entry := range entries {
		if !entry.IsDir() { continue }
		path := filepath.Join(root, entry.Name(), "bluepanel-location.json")
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) { continue }
		if err != nil { return fmt.Errorf("read Tor location state %s: %w", entry.Name(), err) }
		var loc Location
		if err := json.Unmarshal(data, &loc); err != nil { return fmt.Errorf("decode Tor location state %s: %w", entry.Name(), err) }
		if _, err := NormalizeCountry(loc.CountryCode); err != nil { return fmt.Errorf("invalid persisted Tor state %s: %w", entry.Name(), err) }
		loc.ProcessStatus = ProcessStopped
		if !loc.Enabled { loc.HealthStatus = StatusDisabled } else { loc.HealthStatus = StatusStarting }
		copy := loc
		m.instances[loc.ID] = &instance{loc: &copy}
	}
	return nil
}

func (m *Manager) List() []Location {
	m.mu.RLock(); defer m.mu.RUnlock()
	out := make([]Location, 0, len(m.instances))
	for _, inst := range m.instances {
		inst.mu.Lock(); out = append(out, *inst.loc); inst.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SortOrder == out[j].SortOrder { return out[i].Slug < out[j].Slug }
		return out[i].SortOrder < out[j].SortOrder
	})
	return out
}

func (m *Manager) Get(id string) (Location, error) {
	m.mu.RLock(); inst := m.instances[id]; m.mu.RUnlock()
	if inst == nil { return Location{}, fmt.Errorf("Tor location %q not found", id) }
	inst.mu.Lock(); defer inst.mu.Unlock(); return *inst.loc, nil
}

func defaultTags(spec Spec) Spec {
	sum := sha256.Sum256([]byte(spec.ID))
	suffix := hex.EncodeToString(sum[:4])
	if spec.XrayInboundTag == "" { spec.XrayInboundTag = fmt.Sprintf("bluepanel-tor-in-%s-%s", spec.Slug, suffix) }
	if spec.XrayOutboundTag == "" { spec.XrayOutboundTag = fmt.Sprintf("bluepanel-tor-out-%s-%s", spec.Slug, suffix) }
	if spec.XrayRuleTag == "" { spec.XrayRuleTag = fmt.Sprintf("BLUEPANEL_TOR_RULE_%s_%s", strings.ToUpper(spec.Slug), strings.ToUpper(suffix)) }
	return spec
}

func portFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil { return false }
	_ = ln.Close()
	return true
}

func (m *Manager) reservedPorts(exceptID string) map[int]string {
	reserved := make(map[int]string)
	for id, inst := range m.instances {
		if id == exceptID { continue }
		inst.mu.Lock()
		loc := *inst.loc
		inst.mu.Unlock()
		for _, p := range []int{loc.XrayInboundPort, loc.TorSocksPort, loc.TorControlPort} {
			if p > 0 { reserved[p] = id }
		}
	}
	return reserved
}

func allocatePort(r PortRange, reserved map[int]string) (int, error) {
	for p := r.Start; p <= r.End; p++ {
		if _, used := reserved[p]; used { continue }
		if portFree(p) { reserved[p] = "pending"; return p, nil }
	}
	return 0, fmt.Errorf("no free port in range %d-%d", r.Start, r.End)
}

func ensureRequestedPort(port int, reserved map[int]string) error {
	if port < 1 || port > 65535 { return fmt.Errorf("invalid port %d", port) }
	if owner, used := reserved[port]; used { return fmt.Errorf("port %d already reserved by %s", port, owner) }
	if !portFree(port) { return fmt.Errorf("port %d is already in use on host", port) }
	reserved[port] = "pending"
	return nil
}

func (m *Manager) CreateOrUpdate(ctx context.Context, spec Spec) (Location, error) {
	validated, err := ValidateSpec(spec)
	if err != nil { return Location{}, err }
	validated = defaultTags(validated)

	m.mu.Lock()
	defer m.mu.Unlock()

	var existing *instance = m.instances[validated.ID]
	for id, inst := range m.instances {
		if id == validated.ID { continue }
		inst.mu.Lock(); sameSlug := inst.loc.Slug == validated.Slug; inst.mu.Unlock()
		if sameSlug { return Location{}, fmt.Errorf("Tor location slug %q already exists", validated.Slug) }
	}

	reserved := m.reservedPorts(validated.ID)
	if validated.XrayInboundPort == 0 { validated.XrayInboundPort, err = allocatePort(m.cfg.XrayPorts, reserved) } else { err = ensureRequestedPort(validated.XrayInboundPort, reserved) }
	if err != nil { return Location{}, fmt.Errorf("allocate Xray inbound port: %w", err) }
	if validated.TorSocksPort == 0 { validated.TorSocksPort, err = allocatePort(m.cfg.SocksPorts, reserved) } else { err = ensureRequestedPort(validated.TorSocksPort, reserved) }
	if err != nil { return Location{}, fmt.Errorf("allocate Tor SOCKS port: %w", err) }
	if validated.TorControlPort == 0 { validated.TorControlPort, err = allocatePort(m.cfg.ControlPorts, reserved) } else { err = ensureRequestedPort(validated.TorControlPort, reserved) }
	if err != nil { return Location{}, fmt.Errorf("allocate Tor Control port: %w", err) }

	now := time.Now().UTC()
	createdAt := now
	dataDir := m.locationDir(validated.ID, validated.Slug)
	if existing != nil {
		existing.mu.Lock(); createdAt = existing.loc.CreatedAt; dataDir = existing.loc.TorDataDirectory; existing.mu.Unlock()
		// Stop and detach the previous actual state before changing ports/tags/country.
		if err := m.removeActual(existing); err != nil { return Location{}, err }
	}
	loc := &Location{
		ID: validated.ID, Slug: validated.Slug, DisplayName: validated.DisplayName,
		CountryCode: validated.CountryCode, DesiredCountry: validated.CountryCode,
		Enabled: validated.Enabled, SubscriptionEnabled: validated.SubscriptionEnabled, SortOrder: validated.SortOrder,
		BaseInboundTag: validated.BaseInboundTag, XrayInboundPort: validated.XrayInboundPort,
		XrayInboundTag: validated.XrayInboundTag, XrayOutboundTag: validated.XrayOutboundTag, XrayRuleTag: validated.XrayRuleTag,
		TorSocksPort: validated.TorSocksPort, TorControlPort: validated.TorControlPort, TorDataDirectory: dataDir,
		AutoRepair: validated.AutoRepair, CreatedAt: createdAt, UpdatedAt: now, ProcessStatus: ProcessStopped,
	}
	if !loc.Enabled { loc.HealthStatus = StatusDisabled } else { loc.HealthStatus = StatusCreating }
	inst := &instance{loc: loc}
	m.instances[loc.ID] = inst
	if err := m.persist(loc); err != nil { delete(m.instances, loc.ID); return Location{}, fmt.Errorf("persist Tor location: %w", err) }
	if !loc.Enabled { return *loc, nil }
	if err := m.startActual(ctx, inst); err != nil {
		loc.HealthStatus = StatusError; loc.LastError = err.Error(); _ = m.persist(loc)
		return *loc, err
	}
	return *loc, nil
}

func (m *Manager) xrayLocation(loc *Location) XrayLocation {
	return XrayLocation{ID: loc.ID, BaseInboundTag: loc.BaseInboundTag, InboundPort: loc.XrayInboundPort, InboundTag: loc.XrayInboundTag, OutboundTag: loc.XrayOutboundTag, RuleTag: loc.XrayRuleTag, TorSocksPort: loc.TorSocksPort}
}

func torrcQuote(value string) string { return strconv.Quote(value) }

func (m *Manager) GenerateConfig(loc Location) string {
	return strings.Join([]string{
		"ClientOnly 1",
		fmt.Sprintf("SocksPort 127.0.0.1:%d", loc.TorSocksPort),
		fmt.Sprintf("ControlPort 127.0.0.1:%d", loc.TorControlPort),
		"CookieAuthentication 1",
		fmt.Sprintf("DataDirectory %s", torrcQuote(loc.TorDataDirectory)),
		fmt.Sprintf("ExitNodes {%s}", strings.ToLower(loc.DesiredCountry)),
		"StrictNodes 1",
		"AvoidDiskWrites 0",
	}, "\n") + "\n"
}

func (m *Manager) writeAndValidateConfig(ctx context.Context, loc *Location) error {
	if err := os.MkdirAll(loc.TorDataDirectory, 0o700); err != nil { return err }
	torrc := m.GenerateConfig(*loc)
	tmp := m.torrcPath(loc) + ".tmp"
	if err := os.WriteFile(tmp, []byte(torrc), 0o600); err != nil { return err }
	if err := os.Rename(tmp, m.torrcPath(loc)); err != nil { return err }
	validateCtx, cancel := context.WithTimeout(ctx, m.cfg.OperationTimeout)
	defer cancel()
	cmd := exec.CommandContext(validateCtx, m.cfg.ExecutablePath, "--verify-config", "-f", m.torrcPath(loc))
	out, err := cmd.CombinedOutput()
	if err != nil { return fmt.Errorf("Tor config validation failed: %w: %s", err, strings.TrimSpace(string(out))) }
	return nil
}

func (m *Manager) startProcess(ctx context.Context, inst *instance) error {
	inst.mu.Lock()
	if inst.cmd != nil && inst.cmd.Process != nil && inst.cmd.ProcessState == nil {
		inst.mu.Unlock(); return nil
	}
	loc := inst.loc
	loc.ProcessStatus = ProcessStarting
	loc.HealthStatus = StatusStarting
	loc.LastError = ""
	_ = m.persist(loc)
	if err := m.writeAndValidateConfig(ctx, loc); err != nil {
		loc.ProcessStatus = ProcessFailed; loc.LastError = err.Error(); _ = m.persist(loc); inst.mu.Unlock(); return err
	}
	logPath := filepath.Join(loc.TorDataDirectory, "tor.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil { inst.mu.Unlock(); return err }
	cmd := exec.Command(m.cfg.ExecutablePath, "-f", m.torrcPath(loc))
	cmd.Stdout = logFile; cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close(); loc.ProcessStatus = ProcessFailed; loc.LastError = err.Error(); _ = m.persist(loc); inst.mu.Unlock(); return fmt.Errorf("start Tor: %w", err)
	}
	inst.cmd = cmd; inst.logFile = logFile; inst.done = make(chan error, 1)
	loc.ProcessStatus = ProcessRunning
	_ = m.persist(loc)
	done := inst.done
	inst.mu.Unlock()

	go func() {
		err := cmd.Wait()
		done <- err
		close(done)
		inst.mu.Lock()
		if inst.cmd == cmd {
			inst.loc.ProcessStatus = ProcessStopped
			if inst.loc.Enabled {
				inst.loc.HealthStatus = StatusTorDown
				if err != nil { inst.loc.LastError = err.Error() }
			}
			_ = m.persist(inst.loc)
		}
		_ = logFile.Close()
		inst.mu.Unlock()
	}()

	deadline := time.Now().Add(m.cfg.StartupTimeout)
	for time.Now().Before(deadline) {
		probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		err := checkTCPPort(probeCtx, loc.TorSocksPort, time.Second)
		cancel()
		if err == nil { return nil }
		select {
		case err := <-done:
			if err == nil { err = errors.New("Tor exited during startup") }
			return fmt.Errorf("Tor startup failed: %w", err)
		case <-ctx.Done(): return ctx.Err()
		case <-time.After(350 * time.Millisecond):
		}
	}
	return fmt.Errorf("Tor SOCKS port did not become ready within %s", m.cfg.StartupTimeout)
}

func (m *Manager) stopInstance(inst *instance) error {
	inst.mu.Lock()
	cmd := inst.cmd
	if cmd == nil || cmd.Process == nil || cmd.ProcessState != nil {
		inst.loc.ProcessStatus = ProcessStopped; _ = m.persist(inst.loc); inst.mu.Unlock(); return nil
	}
	process := cmd.Process
	inst.mu.Unlock()
	_ = process.Signal(os.Interrupt)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		inst.mu.Lock(); stopped := inst.cmd == nil || inst.cmd.ProcessState != nil; inst.mu.Unlock()
		if stopped { return nil }
		time.Sleep(150 * time.Millisecond)
	}
	if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) { return err }
	return nil
}

func (m *Manager) startActual(ctx context.Context, inst *instance) error {
	if err := m.startProcess(ctx, inst); err != nil { return err }
	if _, err := m.healthTorOnly(ctx, inst); err != nil { _ = m.stopInstance(inst); return err }
	adapter := m.xrayAdapter()
	if adapter == nil { return errors.New("Xray backend is not attached") }
	inst.mu.Lock(); xl := m.xrayLocation(inst.loc); inst.mu.Unlock()
	if err := adapter.ApplyTorLocation(xl); err != nil { _ = m.stopInstance(inst); return fmt.Errorf("apply Tor Xray route: %w", err) }
	if err := adapter.VerifyTorRoute(xl); err != nil { _ = adapter.RemoveTorLocation(xl); _ = m.stopInstance(inst); return fmt.Errorf("verify Tor Xray route: %w", err) }
	_, err := m.HealthCheck(ctx, inst.loc.ID)
	return err
}

func (m *Manager) removeActual(inst *instance) error {
	inst.mu.Lock(); xl := m.xrayLocation(inst.loc); inst.mu.Unlock()
	if adapter := m.xrayAdapter(); adapter != nil {
		if err := adapter.RemoveTorLocation(xl); err != nil { return fmt.Errorf("remove Tor Xray route: %w", err) }
	}
	return m.stopInstance(inst)
}

func (m *Manager) healthTorOnly(ctx context.Context, inst *instance) (ExitObservation, error) {
	inst.mu.Lock(); port := inst.loc.TorSocksPort; expected := inst.loc.DesiredCountry; processRunning := inst.cmd != nil && inst.cmd.Process != nil && inst.cmd.ProcessState == nil; inst.mu.Unlock()
	if !processRunning { return ExitObservation{}, errors.New("Tor process is not running") }
	probeCtx, cancel := context.WithTimeout(ctx, m.cfg.OperationTimeout); defer cancel()
	if err := checkTCPPort(probeCtx, port, 2*time.Second); err != nil { return ExitObservation{}, fmt.Errorf("Tor SOCKS unavailable: %w", err) }
	obs, err := m.verifier.Verify(probeCtx, port)
	if err != nil { return ExitObservation{}, err }
	if m.cfg.CountryVerification && obs.Country != expected { return obs, fmt.Errorf("Tor exit country mismatch: expected %s, detected %s", expected, obs.Country) }
	return obs, nil
}

func (m *Manager) HealthCheck(ctx context.Context, id string) (Location, error) {
	m.mu.RLock(); inst := m.instances[id]; m.mu.RUnlock()
	if inst == nil { return Location{}, fmt.Errorf("Tor location %q not found", id) }
	inst.mu.Lock()
	if !inst.loc.Enabled { inst.loc.HealthStatus = StatusDisabled; _ = m.persist(inst.loc); out := *inst.loc; inst.mu.Unlock(); return out, nil }
	inst.mu.Unlock()

	obs, torErr := m.healthTorOnly(ctx, inst)
	now := time.Now().UTC()
	inst.mu.Lock()
	inst.loc.LastCheckedAt = &now
	if obs.IP != "" { inst.loc.DetectedExitIP = obs.IP }
	if obs.Country != "" { inst.loc.DetectedCountry = obs.Country }
	if obs.LatencyMS > 0 { inst.loc.LatencyMS = obs.LatencyMS }
	if torErr != nil {
		if strings.Contains(torErr.Error(), "country mismatch") { inst.loc.HealthStatus = StatusCountryMismatch } else if strings.Contains(torErr.Error(), "SOCKS") { inst.loc.HealthStatus = StatusTorDown } else { inst.loc.HealthStatus = StatusUnreachable }
		inst.loc.LastError = torErr.Error(); _ = m.persist(inst.loc); out := *inst.loc; inst.mu.Unlock(); return out, torErr
	}
	xl := m.xrayLocation(inst.loc)
	inst.mu.Unlock()

	if adapter := m.xrayAdapter(); adapter == nil {
		inst.mu.Lock(); inst.loc.HealthStatus = StatusXrayError; inst.loc.LastError = "Xray backend is not attached"; _ = m.persist(inst.loc); out := *inst.loc; inst.mu.Unlock(); return out, errors.New("Xray backend is not attached")
	} else if err := adapter.VerifyTorRoute(xl); err != nil {
		inst.mu.Lock(); inst.loc.HealthStatus = StatusXrayError; inst.loc.LastError = err.Error(); _ = m.persist(inst.loc); out := *inst.loc; inst.mu.Unlock(); return out, err
	}
	inst.mu.Lock()
	inst.loc.HealthStatus = StatusHealthy; inst.loc.ProcessStatus = ProcessRunning; inst.loc.LastHealthyAt = &now; inst.loc.LastError = ""; inst.loc.RestartAttempts = 0; inst.loc.NextRepairAt = nil
	_ = m.persist(inst.loc); out := *inst.loc; inst.mu.Unlock(); return out, nil
}

func (m *Manager) Restart(ctx context.Context, id string) (Location, error) {
	m.mu.RLock(); inst := m.instances[id]; m.mu.RUnlock()
	if inst == nil { return Location{}, fmt.Errorf("Tor location %q not found", id) }
	if err := m.removeActual(inst); err != nil { return m.Get(id) }
	inst.mu.Lock(); enabled := inst.loc.Enabled; inst.mu.Unlock()
	if enabled {
		if err := m.startActual(ctx, inst); err != nil { out, _ := m.Get(id); return out, err }
	}
	return m.Get(id)
}

func (m *Manager) NewIdentity(ctx context.Context, id string) (Location, error) {
	m.mu.RLock(); inst := m.instances[id]; m.mu.RUnlock()
	if inst == nil { return Location{}, fmt.Errorf("Tor location %q not found", id) }
	inst.mu.Lock(); control := inst.loc.TorControlPort; dataDir := inst.loc.TorDataDirectory; inst.mu.Unlock()
	if err := signalNewNYM(ctx, control, dataDir, m.cfg.OperationTimeout); err != nil { return m.Get(id) }
	select { case <-ctx.Done(): return m.Get(id); case <-time.After(m.cfg.NewIdentityWait): }
	return m.HealthCheck(ctx, id)
}

func (m *Manager) Enable(ctx context.Context, id string, enabled bool) (Location, error) {
	m.mu.RLock(); inst := m.instances[id]; m.mu.RUnlock()
	if inst == nil { return Location{}, fmt.Errorf("Tor location %q not found", id) }
	inst.mu.Lock(); inst.loc.Enabled = enabled; if !enabled { inst.loc.HealthStatus = StatusDisabled }; _ = m.persist(inst.loc); inst.mu.Unlock()
	if enabled { if err := m.startActual(ctx, inst); err != nil { out, _ := m.Get(id); return out, err } } else if err := m.removeActual(inst); err != nil { out, _ := m.Get(id); return out, err }
	return m.Get(id)
}

func (m *Manager) Repair(ctx context.Context, id string, force bool) (Location, error) {
	m.mu.RLock(); inst := m.instances[id]; m.mu.RUnlock()
	if inst == nil { return Location{}, fmt.Errorf("Tor location %q not found", id) }
	inst.mu.Lock()
	if !inst.loc.Enabled { out := *inst.loc; inst.mu.Unlock(); return out, nil }
	now := time.Now().UTC()
	if !force && inst.loc.NextRepairAt != nil && now.Before(*inst.loc.NextRepairAt) { out := *inst.loc; inst.mu.Unlock(); return out, nil }
	if inst.loc.RestartAttempts >= m.cfg.MaxRestartAttempts && !force { out := *inst.loc; inst.mu.Unlock(); return out, fmt.Errorf("maximum Tor repair attempts reached") }
	inst.loc.HealthStatus = StatusRepairing; previousStatus := inst.loc.HealthStatus; _ = previousStatus; _ = m.persist(inst.loc); inst.mu.Unlock()

	// Country mismatches get a cheap NEWNYM attempt before a process restart.
	current, _ := m.Get(id)
	if current.DetectedCountry != "" && current.DetectedCountry != current.DesiredCountry {
		if updated, err := m.NewIdentity(ctx, id); err == nil && updated.HealthStatus == StatusHealthy { return updated, nil }
	}
	updated, err := m.Restart(ctx, id)
	if err == nil && updated.HealthStatus == StatusHealthy { return updated, nil }

	inst.mu.Lock()
	inst.loc.RestartAttempts++
	idx := inst.loc.RestartAttempts - 1; if idx >= len(m.cfg.RestartBackoff) { idx = len(m.cfg.RestartBackoff)-1 }
	next := time.Now().UTC().Add(m.cfg.RestartBackoff[idx]); inst.loc.NextRepairAt = &next
	if err != nil { inst.loc.LastError = err.Error() }
	_ = m.persist(inst.loc); out := *inst.loc; inst.mu.Unlock(); return out, err
}

func (m *Manager) Delete(ctx context.Context, id string, purgeData bool) error {
	m.mu.RLock(); inst := m.instances[id]; m.mu.RUnlock()
	if inst == nil { return nil }
	inst.mu.Lock(); inst.loc.HealthStatus = StatusDeleting; _ = m.persist(inst.loc); inst.mu.Unlock()
	if err := m.removeActual(inst); err != nil {
		inst.mu.Lock(); inst.loc.HealthStatus = StatusCleanupFailed; inst.loc.LastError = err.Error(); _ = m.persist(inst.loc); inst.mu.Unlock(); return err
	}
	inst.mu.Lock(); dataDir := inst.loc.TorDataDirectory; inst.mu.Unlock()
	m.mu.Lock(); delete(m.instances, id); m.mu.Unlock()
	if purgeData { return os.RemoveAll(dataDir) }
	retained := filepath.Join(m.cfg.DataRoot, "retained", filepath.Base(dataDir)+"-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := os.Rename(dataDir, retained); err != nil && !errors.Is(err, fs.ErrNotExist) { return err }
	return nil
}

func (m *Manager) Reconcile(ctx context.Context) error {
	m.mu.RLock(); ids := make([]string, 0, len(m.instances)); for id := range m.instances { ids = append(ids, id) }; m.mu.RUnlock(); sort.Strings(ids)
	var errs []string
	for _, id := range ids {
		select { case <-ctx.Done(): return ctx.Err(); default: }
		loc, _ := m.Get(id)
		if !loc.Enabled {
			m.mu.RLock(); inst := m.instances[id]; m.mu.RUnlock(); if inst != nil { if err := m.removeActual(inst); err != nil { errs = append(errs, id+": "+err.Error()) } }
			continue
		}
		if _, err := m.HealthCheck(ctx, id); err == nil { continue }
		m.mu.RLock(); inst := m.instances[id]; m.mu.RUnlock()
		if inst != nil {
			if err := m.startActual(ctx, inst); err != nil { errs = append(errs, id+": "+err.Error()) }
		}
	}
	if len(errs) > 0 { return errors.New(strings.Join(errs, "; ")) }
	return nil
}

// Recover starts enabled persisted locations with bounded concurrency and a small
// stagger so 20-50 locations do not bootstrap simultaneously after a reboot.
func (m *Manager) Recover(ctx context.Context) error {
	m.mu.RLock(); ids := make([]string, 0, len(m.instances)); for id, inst := range m.instances { inst.mu.Lock(); enabled := inst.loc.Enabled; inst.mu.Unlock(); if enabled { ids = append(ids, id) } }; m.mu.RUnlock(); sort.Strings(ids)
	sem := make(chan struct{}, m.cfg.StartupConcurrency)
	var wg sync.WaitGroup; var errsMu sync.Mutex; var errs []string
	for idx, id := range ids {
		select { case <-ctx.Done(): return ctx.Err(); case <-time.After(time.Duration(idx%5)*250*time.Millisecond): }
		wg.Add(1); go func(id string) { defer wg.Done(); sem <- struct{}{}; defer func(){ <-sem }(); m.mu.RLock(); inst := m.instances[id]; m.mu.RUnlock(); if inst == nil { return }; if err := m.startActual(ctx, inst); err != nil { errsMu.Lock(); errs = append(errs, id+": "+err.Error()); errsMu.Unlock() } }(id)
	}
	wg.Wait(); if len(errs) > 0 { return errors.New(strings.Join(errs, "; ")) }; return nil
}

func (m *Manager) healthLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.cfg.HealthCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done(): return
		case <-ticker.C:
			locations := m.List()
			for idx := range locations {
				loc := locations[idx]
				if !loc.Enabled { continue }
				select { case <-m.ctx.Done(): return; case <-time.After(time.Duration(idx%7)*150*time.Millisecond): }
				ctx, cancel := context.WithTimeout(m.ctx, m.cfg.OperationTimeout+10*time.Second)
				updated, err := m.HealthCheck(ctx, loc.ID)
				cancel()
				if err != nil && m.cfg.AutoRepair && updated.AutoRepair {
					ctx, cancel = context.WithTimeout(m.ctx, m.cfg.StartupTimeout+m.cfg.OperationTimeout+15*time.Second)
					if _, repairErr := m.Repair(ctx, loc.ID, false); repairErr != nil { log.Printf("tor location_id=%s country=%s action=auto_repair result=error error=%q", loc.ID, loc.CountryCode, repairErr) }
					cancel()
				}
			}
		}
	}
}
