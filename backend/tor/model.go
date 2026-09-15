package tor

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// HealthStatus is the externally visible lifecycle/health state of a Tor location.
type HealthStatus string

const (
	StatusCreating        HealthStatus = "creating"
	StatusStarting        HealthStatus = "starting"
	StatusHealthy         HealthStatus = "healthy"
	StatusDegraded        HealthStatus = "degraded"
	StatusCountryMismatch HealthStatus = "country_mismatch"
	StatusTorDown         HealthStatus = "tor_down"
	StatusXrayError       HealthStatus = "xray_error"
	StatusUnreachable     HealthStatus = "unreachable"
	StatusDisabled        HealthStatus = "disabled"
	StatusRepairing       HealthStatus = "repairing"
	StatusDeleting        HealthStatus = "deleting"
	StatusCleanupFailed   HealthStatus = "cleanup_failed"
	StatusError           HealthStatus = "error"
)

// ProcessStatus captures only process lifecycle and is intentionally independent
// from end-to-end health (SOCKS, country and Xray routing).
type ProcessStatus string

const (
	ProcessStopped ProcessStatus = "stopped"
	ProcessStarting ProcessStatus = "starting"
	ProcessRunning ProcessStatus = "running"
	ProcessFailed  ProcessStatus = "failed"
)

// Location is the durable Node-side desired/observed state. The Panel remains the
// product source of truth; this persisted copy exists so enabled locations recover
// after a Node/container restart even while the Panel is temporarily unavailable.
type Location struct {
	ID                  string        `json:"id"`
	Slug                string        `json:"slug"`
	DisplayName         string        `json:"display_name"`
	CountryCode         string        `json:"country_code"`
	Enabled             bool          `json:"enabled"`
	SubscriptionEnabled bool          `json:"subscription_enabled"`
	SortOrder           int32         `json:"sort_order"`
	BaseInboundTag      string        `json:"base_inbound_tag"`
	XrayInboundPort     int           `json:"xray_inbound_port"`
	XrayInboundTag      string        `json:"xray_inbound_tag"`
	XrayOutboundTag     string        `json:"xray_outbound_tag"`
	XrayRuleTag         string        `json:"xray_rule_tag"`
	TorSocksPort        int           `json:"tor_socks_port"`
	TorControlPort      int           `json:"tor_control_port"`
	TorDataDirectory    string        `json:"tor_data_directory"`
	DesiredCountry      string        `json:"desired_country"`
	DetectedCountry     string        `json:"detected_country,omitempty"`
	DetectedExitIP      string        `json:"detected_exit_ip,omitempty"`
	HealthStatus        HealthStatus  `json:"health_status"`
	ProcessStatus       ProcessStatus `json:"process_status"`
	LatencyMS           int64         `json:"latency_ms,omitempty"`
	AutoRepair          bool          `json:"auto_repair"`
	LastCheckedAt       *time.Time    `json:"last_checked_at,omitempty"`
	LastHealthyAt       *time.Time    `json:"last_healthy_at,omitempty"`
	LastError           string        `json:"last_error,omitempty"`
	RestartAttempts     int           `json:"restart_attempts"`
	NextRepairAt        *time.Time    `json:"next_repair_at,omitempty"`
	CreatedAt           time.Time     `json:"created_at"`
	UpdatedAt           time.Time     `json:"updated_at"`
}

// Spec is the idempotent create/update request accepted by Manager.
type Spec struct {
	ID                  string
	Slug                string
	DisplayName         string
	CountryCode         string
	Enabled             bool
	SubscriptionEnabled bool
	SortOrder           int32
	BaseInboundTag      string
	XrayInboundPort     int
	XrayInboundTag      string
	XrayOutboundTag     string
	XrayRuleTag         string
	TorSocksPort        int
	TorControlPort      int
	AutoRepair          bool
}

// XrayLocation is the narrow contract sent to the existing Xray backend. Keeping
// the adapter typed prevents Tor lifecycle code from manipulating the whole Xray
// config or importing the Xray implementation package.
type XrayLocation struct {
	ID              string
	BaseInboundTag  string
	InboundPort     int
	InboundTag      string
	OutboundTag     string
	RuleTag         string
	TorSocksPort    int
}

// XrayAdapter is implemented by backend/xray. Apply/Remove must be idempotent and
// internally use the existing config clone + restart + rollback path.
type XrayAdapter interface {
	ApplyTorLocation(location XrayLocation) error
	RemoveTorLocation(location XrayLocation) error
	VerifyTorRoute(location XrayLocation) error
}

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ISO3166Alpha2 contains the assignable ISO-3166-1 alpha-2 country codes. Tor's
// ExitNodes accepts these two-letter country selectors. Values are intentionally
// static and user input is never interpolated unless present in this whitelist.
var ISO3166Alpha2 = map[string]struct{}{
	"AD": {}, "AE": {}, "AF": {}, "AG": {}, "AI": {}, "AL": {}, "AM": {}, "AO": {}, "AQ": {}, "AR": {}, "AS": {}, "AT": {}, "AU": {}, "AW": {}, "AX": {}, "AZ": {},
	"BA": {}, "BB": {}, "BD": {}, "BE": {}, "BF": {}, "BG": {}, "BH": {}, "BI": {}, "BJ": {}, "BL": {}, "BM": {}, "BN": {}, "BO": {}, "BQ": {}, "BR": {}, "BS": {}, "BT": {}, "BV": {}, "BW": {}, "BY": {}, "BZ": {},
	"CA": {}, "CC": {}, "CD": {}, "CF": {}, "CG": {}, "CH": {}, "CI": {}, "CK": {}, "CL": {}, "CM": {}, "CN": {}, "CO": {}, "CR": {}, "CU": {}, "CV": {}, "CW": {}, "CX": {}, "CY": {}, "CZ": {},
	"DE": {}, "DJ": {}, "DK": {}, "DM": {}, "DO": {}, "DZ": {}, "EC": {}, "EE": {}, "EG": {}, "EH": {}, "ER": {}, "ES": {}, "ET": {}, "FI": {}, "FJ": {}, "FK": {}, "FM": {}, "FO": {}, "FR": {},
	"GA": {}, "GB": {}, "GD": {}, "GE": {}, "GF": {}, "GG": {}, "GH": {}, "GI": {}, "GL": {}, "GM": {}, "GN": {}, "GP": {}, "GQ": {}, "GR": {}, "GS": {}, "GT": {}, "GU": {}, "GW": {}, "GY": {},
	"HK": {}, "HM": {}, "HN": {}, "HR": {}, "HT": {}, "HU": {}, "ID": {}, "IE": {}, "IL": {}, "IM": {}, "IN": {}, "IO": {}, "IQ": {}, "IR": {}, "IS": {}, "IT": {}, "JE": {}, "JM": {}, "JO": {}, "JP": {},
	"KE": {}, "KG": {}, "KH": {}, "KI": {}, "KM": {}, "KN": {}, "KP": {}, "KR": {}, "KW": {}, "KY": {}, "KZ": {}, "LA": {}, "LB": {}, "LC": {}, "LI": {}, "LK": {}, "LR": {}, "LS": {}, "LT": {}, "LU": {}, "LV": {}, "LY": {},
	"MA": {}, "MC": {}, "MD": {}, "ME": {}, "MF": {}, "MG": {}, "MH": {}, "MK": {}, "ML": {}, "MM": {}, "MN": {}, "MO": {}, "MP": {}, "MQ": {}, "MR": {}, "MS": {}, "MT": {}, "MU": {}, "MV": {}, "MW": {}, "MX": {}, "MY": {}, "MZ": {},
	"NA": {}, "NC": {}, "NE": {}, "NF": {}, "NG": {}, "NI": {}, "NL": {}, "NO": {}, "NP": {}, "NR": {}, "NU": {}, "NZ": {}, "OM": {}, "PA": {}, "PE": {}, "PF": {}, "PG": {}, "PH": {}, "PK": {}, "PL": {}, "PM": {}, "PN": {}, "PR": {}, "PS": {}, "PT": {}, "PW": {}, "PY": {},
	"QA": {}, "RE": {}, "RO": {}, "RS": {}, "RU": {}, "RW": {}, "SA": {}, "SB": {}, "SC": {}, "SD": {}, "SE": {}, "SG": {}, "SH": {}, "SI": {}, "SJ": {}, "SK": {}, "SL": {}, "SM": {}, "SN": {}, "SO": {}, "SR": {}, "SS": {}, "ST": {}, "SV": {}, "SX": {}, "SY": {}, "SZ": {},
	"TC": {}, "TD": {}, "TF": {}, "TG": {}, "TH": {}, "TJ": {}, "TK": {}, "TL": {}, "TM": {}, "TN": {}, "TO": {}, "TR": {}, "TT": {}, "TV": {}, "TW": {}, "TZ": {}, "UA": {}, "UG": {}, "UM": {}, "US": {}, "UY": {}, "UZ": {}, "VA": {}, "VC": {}, "VE": {}, "VG": {}, "VI": {}, "VN": {}, "VU": {},
	"WF": {}, "WS": {}, "YE": {}, "YT": {}, "ZA": {}, "ZM": {}, "ZW": {},
}

func NormalizeCountry(country string) (string, error) {
	country = strings.ToUpper(strings.TrimSpace(country))
	if _, ok := ISO3166Alpha2[country]; !ok {
		return "", fmt.Errorf("invalid ISO-3166 alpha-2 country code %q", country)
	}
	return country, nil
}

func ValidateSpec(spec Spec) (Spec, error) {
	if strings.TrimSpace(spec.ID) == "" {
		return spec, errors.New("location id is required")
	}
	spec.Slug = strings.ToLower(strings.TrimSpace(spec.Slug))
	if !slugPattern.MatchString(spec.Slug) {
		return spec, fmt.Errorf("invalid location slug %q", spec.Slug)
	}
	country, err := NormalizeCountry(spec.CountryCode)
	if err != nil {
		return spec, err
	}
	spec.CountryCode = country
	if strings.TrimSpace(spec.BaseInboundTag) == "" {
		return spec, errors.New("base inbound tag is required")
	}
	return spec, nil
}
