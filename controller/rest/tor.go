package rest

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	tormgr "github.com/pasarguard/node/backend/tor"
	"github.com/pasarguard/node/common"
)

func torLocationProto(loc tormgr.Location) *common.TorLocation {
	lastChecked := int64(0)
	if loc.LastCheckedAt != nil {
		lastChecked = loc.LastCheckedAt.Unix()
	}
	lastHealthy := int64(0)
	if loc.LastHealthyAt != nil {
		lastHealthy = loc.LastHealthyAt.Unix()
	}
	return &common.TorLocation{
		Id:                  loc.ID,
		Slug:                loc.Slug,
		DisplayName:         loc.DisplayName,
		CountryCode:         loc.CountryCode,
		Enabled:             loc.Enabled,
		SubscriptionEnabled: loc.SubscriptionEnabled,
		SortOrder:           loc.SortOrder,
		BaseInboundTag:      loc.BaseInboundTag,
		XrayInboundPort:     uint32(loc.XrayInboundPort),
		XrayInboundTag:      loc.XrayInboundTag,
		XrayOutboundTag:     loc.XrayOutboundTag,
		XrayRuleTag:         loc.XrayRuleTag,
		TorSocksPort:        uint32(loc.TorSocksPort),
		TorControlPort:      uint32(loc.TorControlPort),
		TorDataDirectory:    loc.TorDataDirectory,
		DesiredCountry:      loc.DesiredCountry,
		DetectedCountry:     loc.DetectedCountry,
		DetectedExitIp:      loc.DetectedExitIP,
		HealthStatus:        string(loc.HealthStatus),
		LatencyMs:           loc.LatencyMS,
		ProcessStatus:       string(loc.ProcessStatus),
		LastCheckedAt:       lastChecked,
		LastHealthyAt:       lastHealthy,
		LastError:           loc.LastError,
		AutoRepair:          loc.AutoRepair,
		RestartAttempts:     int32(loc.RestartAttempts),
		CreatedAt:           loc.CreatedAt.Unix(),
		UpdatedAt:           loc.UpdatedAt.Unix(),
	}
}

func torSpecFromProto(req *common.TorLocationSpec) tormgr.Spec {
	return tormgr.Spec{
		ID:                  req.GetId(),
		Slug:                req.GetSlug(),
		DisplayName:         req.GetDisplayName(),
		CountryCode:         req.GetCountryCode(),
		Enabled:             req.GetEnabled(),
		SubscriptionEnabled: req.GetSubscriptionEnabled(),
		SortOrder:           req.GetSortOrder(),
		BaseInboundTag:      req.GetBaseInboundTag(),
		XrayInboundPort:     int(req.GetXrayInboundPort()),
		XrayInboundTag:      req.GetXrayInboundTag(),
		XrayOutboundTag:     req.GetXrayOutboundTag(),
		XrayRuleTag:         req.GetXrayRuleTag(),
		TorSocksPort:        int(req.GetTorSocksPort()),
		TorControlPort:      int(req.GetTorControlPort()),
		AutoRepair:          req.GetAutoRepair(),
	}
}

func (s *Service) torManagerOrHTTPError(w http.ResponseWriter) *tormgr.Manager {
	manager, err := s.TorManager()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return nil
	}
	return manager
}

func (s *Service) ListTorLocations(w http.ResponseWriter, _ *http.Request) {
	manager := s.torManagerOrHTTPError(w)
	if manager == nil {
		return
	}
	locations := manager.List()
	resp := &common.TorLocationsResponse{Locations: make([]*common.TorLocation, 0, len(locations))}
	for _, loc := range locations {
		resp.Locations = append(resp.Locations, torLocationProto(loc))
	}
	common.SendProtoResponse(w, resp)
}

func (s *Service) GetTorLocation(w http.ResponseWriter, r *http.Request) {
	manager := s.torManagerOrHTTPError(w)
	if manager == nil {
		return
	}
	loc, err := manager.Get(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	common.SendProtoResponse(w, torLocationProto(loc))
}

func (s *Service) CreateOrUpdateTorLocation(w http.ResponseWriter, r *http.Request) {
	manager := s.torManagerOrHTTPError(w)
	if manager == nil {
		return
	}
	var req common.TorLocationSpec
	if err := common.ReadProtoBody(r.Body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPut {
		if _, err := manager.Get(req.GetId()); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	}
	loc, err := manager.CreateOrUpdate(r.Context(), torSpecFromProto(&req))
	if err != nil {
		// Validation/collision errors are client errors; process/Xray failures may
		// still return useful observed state but are operational failures.
		if loc.ID == "" {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("X-BluePanel-Tor-Error", err.Error())
		w.WriteHeader(http.StatusServiceUnavailable)
		common.SendProtoResponse(w, torLocationProto(loc))
		return
	}
	common.SendProtoResponse(w, torLocationProto(loc))
}

func (s *Service) DeleteTorLocation(w http.ResponseWriter, r *http.Request) {
	manager := s.torManagerOrHTTPError(w)
	if manager == nil {
		return
	}
	purge, _ := strconv.ParseBool(r.URL.Query().Get("purge_data"))
	if err := manager.Delete(r.Context(), chi.URLParam(r, "id"), purge); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	common.SendProtoResponse(w, &common.Empty{})
}

func (s *Service) torLocationAction(w http.ResponseWriter, r *http.Request, action string) {
	manager := s.torManagerOrHTTPError(w)
	if manager == nil {
		return
	}
	id := chi.URLParam(r, "id")
	var (
		loc tormgr.Location
		err error
	)
	switch action {
	case "enable":
		loc, err = manager.Enable(r.Context(), id, true)
	case "disable":
		loc, err = manager.Enable(r.Context(), id, false)
	case "restart":
		loc, err = manager.Restart(r.Context(), id)
	case "new-identity":
		loc, err = manager.NewIdentity(r.Context(), id)
	case "health", "test":
		loc, err = manager.HealthCheck(r.Context(), id)
	case "repair":
		loc, err = manager.Repair(r.Context(), id, true)
	default:
		http.Error(w, "unsupported Tor location action", http.StatusNotFound)
		return
	}
	if err != nil {
		if loc.ID == "" {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("X-BluePanel-Tor-Error", err.Error())
		w.WriteHeader(http.StatusServiceUnavailable)
		common.SendProtoResponse(w, torLocationProto(loc))
		return
	}
	common.SendProtoResponse(w, torLocationProto(loc))
}

func (s *Service) EnableTorLocation(w http.ResponseWriter, r *http.Request) {
	s.torLocationAction(w, r, "enable")
}
func (s *Service) DisableTorLocation(w http.ResponseWriter, r *http.Request) {
	s.torLocationAction(w, r, "disable")
}
func (s *Service) RestartTorLocation(w http.ResponseWriter, r *http.Request) {
	s.torLocationAction(w, r, "restart")
}
func (s *Service) NewTorIdentity(w http.ResponseWriter, r *http.Request) {
	s.torLocationAction(w, r, "new-identity")
}
func (s *Service) GetTorHealth(w http.ResponseWriter, r *http.Request) {
	s.torLocationAction(w, r, "health")
}
func (s *Service) RepairTorLocation(w http.ResponseWriter, r *http.Request) {
	s.torLocationAction(w, r, "repair")
}
func (s *Service) TestTorLocation(w http.ResponseWriter, r *http.Request) {
	s.torLocationAction(w, r, "test")
}

func (s *Service) ForceReconcileTor(w http.ResponseWriter, r *http.Request) {
	manager := s.torManagerOrHTTPError(w)
	if manager == nil {
		return
	}
	err := manager.Reconcile(r.Context())
	locations := manager.List()
	resp := &common.TorReconcileResponse{Locations: make([]*common.TorLocation, 0, len(locations))}
	for _, loc := range locations {
		resp.Locations = append(resp.Locations, torLocationProto(loc))
	}
	if err != nil {
		w.Header().Set("X-BluePanel-Tor-Error", err.Error())
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	common.SendProtoResponse(w, resp)
}
