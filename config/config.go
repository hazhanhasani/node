package config

import (
	"log"
	"os"
	"regexp"
	"strconv"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

type Config struct {
	ServicePort                 int
	NodeHost                    string
	XrayExecutablePath          string
	XrayAssetsPath              string
	SslCertFile                 string
	SslKeyFile                  string
	ApiKey                      uuid.UUID
	ServiceProtocol             string
	Debug                       bool
	GeneratedConfigPath         string
	LogBufferSize               int
	StartupLogTailSize          int
	StatsUpdateIntervalSeconds  int
	StatsCleanupIntervalSeconds int

	// WireGuard host routing (Linux). See .env.example for semantics.
	WGHostRouting        bool
	WGNATOutputInterface string
	WGNATEgressOnly      bool
	WGNATDisable         bool
	WGRouteTable         string
	WGRouteOutInterface  string

	// Tor Multi-Exit is feature-gated and disabled by default. Port ranges are
	// Node-side safety/automatic-allocation bounds; the Panel also persists
	// reservations transactionally.
	TorMultiExitEnabled          bool
	TorExecutablePath            string
	TorDataRoot                  string
	TorXrayPortStart             int
	TorXrayPortEnd               int
	TorSocksPortStart            int
	TorSocksPortEnd              int
	TorControlPortStart          int
	TorControlPortEnd            int
	TorHealthCheckIntervalSec    int
	TorStartupTimeoutSec         int
	TorOperationTimeoutSec       int
	TorNewIdentityWaitSec        int
	TorMaxRestartAttempts        int
	TorStartupConcurrency        int
	TorCountryVerification       bool
	TorAutoRepair                bool
}

func Load() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		log.Printf("[Warning] Failed to load env file, if you're using 'Docker' and you set 'environment' or 'env_file' variable, don't worry, everything is fine. Error: %v", err)
	}

	cfg := &Config{
		ServicePort:                 GetEnvAsInt("SERVICE_PORT", 62050),
		XrayExecutablePath:          GetEnv("XRAY_EXECUTABLE_PATH", "/usr/local/bin/xray"),
		XrayAssetsPath:              GetEnv("XRAY_ASSETS_PATH", "/usr/local/share/xray"),
		SslCertFile:                 GetEnv("SSL_CERT_FILE", "/var/lib/pg-node/certs/ssl_cert.pem"),
		SslKeyFile:                  GetEnv("SSL_KEY_FILE", "/var/lib/pg-node/certs/ssl_key.pem"),
		GeneratedConfigPath:         GetEnv("GENERATED_CONFIG_PATH", "/var/lib/pg-node/generated/"),
		ServiceProtocol:             GetEnv("SERVICE_PROTOCOL", "grpc"),
		Debug:                       GetEnvAsBool("DEBUG", false),
		LogBufferSize:               GetEnvAsInt("LOG_BUFFER_SIZE", 10000),
		StartupLogTailSize:          GetEnvAsInt("STARTUP_LOG_TAIL_SIZE", 200),
		StatsUpdateIntervalSeconds:  GetEnvAsInt("STATS_UPDATE_INTERVAL_SECONDS", 10),
		StatsCleanupIntervalSeconds: GetEnvAsInt("STATS_CLEANUP_INTERVAL_SECONDS", 300),

		WGHostRouting:        GetEnvAsBool("PG_NODE_WG_HOST_ROUTING", true),
		WGNATOutputInterface: GetEnv("PG_NODE_WG_NAT_OUTPUT_INTERFACE", ""),
		WGNATEgressOnly:      GetEnvAsBool("PG_NODE_WG_NAT_EGRESS_ONLY", true),
		WGNATDisable:         GetEnvAsBool("PG_NODE_WG_NAT_DISABLE", false),
		WGRouteTable:         GetEnv("PG_NODE_WG_ROUTE_TABLE", ""),
		WGRouteOutInterface:  GetEnv("PG_NODE_WG_ROUTE_OUT_INTERFACE", ""),

		TorMultiExitEnabled:       GetEnvAsBool("TOR_MULTI_EXIT_ENABLED", false),
		TorExecutablePath:         GetEnv("TOR_EXECUTABLE_PATH", "/usr/bin/tor"),
		TorDataRoot:               GetEnv("TOR_DATA_ROOT", "/var/lib/bluepanel-node/tor"),
		TorXrayPortStart:          GetEnvAsInt("TOR_XRAY_PORT_START", 31000),
		TorXrayPortEnd:            GetEnvAsInt("TOR_XRAY_PORT_END", 31999),
		TorSocksPortStart:         GetEnvAsInt("TOR_SOCKS_PORT_START", 19000),
		TorSocksPortEnd:           GetEnvAsInt("TOR_SOCKS_PORT_END", 19999),
		TorControlPortStart:       GetEnvAsInt("TOR_CONTROL_PORT_START", 20000),
		TorControlPortEnd:         GetEnvAsInt("TOR_CONTROL_PORT_END", 20999),
		TorHealthCheckIntervalSec: GetEnvAsInt("TOR_HEALTH_CHECK_INTERVAL_SECONDS", 60),
		TorStartupTimeoutSec:      GetEnvAsInt("TOR_STARTUP_TIMEOUT_SECONDS", 45),
		TorOperationTimeoutSec:    GetEnvAsInt("TOR_OPERATION_TIMEOUT_SECONDS", 15),
		TorNewIdentityWaitSec:     GetEnvAsInt("TOR_NEW_IDENTITY_WAIT_SECONDS", 5),
		TorMaxRestartAttempts:     GetEnvAsInt("TOR_MAX_RESTART_ATTEMPTS", 5),
		TorStartupConcurrency:     GetEnvAsInt("TOR_STARTUP_CONCURRENCY", 3),
		TorCountryVerification:    GetEnvAsBool("TOR_COUNTRY_VERIFICATION", true),
		TorAutoRepair:             GetEnvAsBool("TOR_AUTO_REPAIR", true),
	}

	if cfg.LogBufferSize <= 0 {
		log.Printf("[Warning] LOG_BUFFER_SIZE must be greater than 0, got %d. Falling back to 1.", cfg.LogBufferSize)
		cfg.LogBufferSize = 1
	}

	cfg.ApiKey, err = GetEnvAsUUID("API_KEY")
	if err != nil {
		log.Printf("[Error] Failed to load API Key, error: %v", err)
	}

	nodeHostStr := GetEnv("NODE_HOST", "0.0.0.0")
	ipPattern := `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	re := regexp.MustCompile(ipPattern)

	if re.MatchString(nodeHostStr) {
		cfg.NodeHost = nodeHostStr
	} else {
		log.Println(nodeHostStr, " is not a valid IP address.\n NODE_HOST will be set to 127.0.0.1")
		cfg.NodeHost = "127.0.0.1"
	}

	return cfg, nil
}

// NewTestConfig creates a config for testing
func NewTestConfig(generatedConfigPath string, key uuid.UUID) *Config {
	cfg, _ := Load()
	cfg.GeneratedConfigPath = generatedConfigPath
	cfg.ApiKey = key
	return cfg
}

func GetEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

func GetEnvAsBool(name string, defaultVal bool) bool {
	valStr := GetEnv(name, "")
	if val, err := strconv.ParseBool(valStr); err == nil {
		return val
	}
	return defaultVal
}

func GetEnvAsInt(name string, defaultVal int) int {
	valStr := GetEnv(name, "")
	if val, err := strconv.Atoi(valStr); err == nil {
		return val
	}
	return defaultVal
}

func GetEnvAsUUID(name string) (uuid.UUID, error) {
	valStr := GetEnv(name, "")

	val, err := uuid.Parse(valStr)
	if err != nil {
		return uuid.Nil, err
	}
	return val, nil
}
