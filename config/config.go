package config

import (
	"flag"
	"fmt"
	"os"
	"runtime"
)

type Config struct {
	Port          int
	DBPath        string
	FirewallMode  string
	AutoSync      bool
	LogLevel      string
	TrustedProxy  string
}

const (
	ModeAuto    = "auto"
	ModeNetsh   = "netsh"
	ModeMock    = "mock"
)

func Load() *Config {
	cfg := &Config{}

	flag.IntVar(&cfg.Port, "port", getEnvInt("SG_PORT", 8080), "HTTP server port")
	flag.StringVar(&cfg.DBPath, "db", getEnvString("SG_DB_PATH", "securitygroup.db"), "SQLite database path")
	flag.StringVar(&cfg.FirewallMode, "firewall", getEnvString("SG_FIREWALL_MODE", ModeAuto),
		fmt.Sprintf("Firewall backend mode: %s/%s/%s", ModeAuto, ModeNetsh, ModeMock))
	flag.BoolVar(&cfg.AutoSync, "autosync", getEnvBool("SG_AUTO_SYNC", true), "Auto sync rules on startup")
	flag.StringVar(&cfg.LogLevel, "log", getEnvString("SG_LOG_LEVEL", "info"), "Log level: debug/info/warn/error")
	flag.StringVar(&cfg.TrustedProxy, "proxy", getEnvString("SG_TRUSTED_PROXY", ""), "Trusted proxy CIDR")

	flag.Parse()

	if cfg.FirewallMode == ModeAuto {
		if runtime.GOOS == "windows" {
			cfg.FirewallMode = ModeNetsh
		} else {
			cfg.FirewallMode = ModeMock
		}
	}

	return cfg
}

func (c *Config) Validate() error {
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}
	if c.DBPath == "" {
		return fmt.Errorf("db path is required")
	}
	switch c.FirewallMode {
	case ModeNetsh, ModeMock:
	default:
		return fmt.Errorf("invalid firewall mode: %s", c.FirewallMode)
	}
	return nil
}

func getEnvString(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if v := os.Getenv(key); v != "" {
		switch v {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return defaultValue
}
