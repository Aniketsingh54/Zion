package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all Zion runtime configuration loaded from config.yaml.
type Config struct {
	Whitelist WhitelistConfig `yaml:"whitelist"`
	Response  ResponseConfig  `yaml:"response"`
	Logging   LoggingConfig   `yaml:"logging"`
	Verbose   bool            `yaml:"verbose"`
}

// WhitelistConfig holds process whitelists.
type WhitelistConfig struct {
	Exec       []string `yaml:"exec"`
	Escalation []string `yaml:"escalation"`
}

// ResponseConfig holds automated response settings.
type ResponseConfig struct {
	AutoKill        bool   `yaml:"auto_kill"`
	CaptureTraffic  bool   `yaml:"capture_traffic"`
	CaptureDuration int    `yaml:"capture_duration"`
	EnforcerSocket  string `yaml:"enforcer_socket"`
}

// LoggingConfig holds JSON event logging settings.
type LoggingConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Directory string `yaml:"directory"`
	Format    string `yaml:"format"`
}

// Runtime overrides applied via CLI flags.
type RuntimeOverrides struct {
	NoKill  bool
	Verbose bool
	LogDir  string
	Stats   bool
}

// Merged combines Config + CLI overrides into the final runtime settings.
type Merged struct {
	Config
	NoKill bool
	Stats  bool

	// Internal lookup maps (built once at startup)
	execWhitelist     map[string]bool
	escalationAllowed map[string]bool
}

// Load reads and parses a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config %s: %w", path, err)
	}

	cfg := &Config{
		// Defaults
		Response: ResponseConfig{
			AutoKill:        true,
			CaptureTraffic:  true,
			CaptureDuration: 60,
			EnforcerSocket:  "/tmp/zion_enforcer.sock",
		},
		Logging: LoggingConfig{
			Enabled:   true,
			Directory: "./logs",
			Format:    "jsonl",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config %s: %w", path, err)
	}

	return cfg, nil
}

// Merge combines a Config with CLI runtime overrides into the final Merged config.
func Merge(cfg *Config, overrides RuntimeOverrides) *Merged {
	m := &Merged{
		Config: *cfg,
		Stats:  overrides.Stats,
	}

	// CLI flags override file config
	if overrides.NoKill {
		m.NoKill = true
		m.Config.Response.AutoKill = false
	}
	if overrides.Verbose {
		m.Config.Verbose = true
	}
	if overrides.LogDir != "" {
		m.Config.Logging.Directory = overrides.LogDir
	}

	// Build lookup maps for O(1) checks
	m.execWhitelist = make(map[string]bool, len(cfg.Whitelist.Exec))
	for _, comm := range cfg.Whitelist.Exec {
		m.execWhitelist[comm] = true
	}

	m.escalationAllowed = make(map[string]bool, len(cfg.Whitelist.Escalation))
	for _, comm := range cfg.Whitelist.Escalation {
		m.escalationAllowed[comm] = true
	}

	return m
}

// IsExecWhitelisted returns true if the command should be silently ignored.
func (m *Merged) IsExecWhitelisted(comm string) bool {
	return m.execWhitelist[comm]
}

// IsEscalationAllowed returns true if the binary is expected to call setuid(0).
func (m *Merged) IsEscalationAllowed(comm string) bool {
	return m.escalationAllowed[comm]
}

// ShouldAutoKill returns true if automated response is enabled.
func (m *Merged) ShouldAutoKill() bool {
	return m.Config.Response.AutoKill && !m.NoKill
}

// SocketPath returns the configured enforcer socket path.
func (m *Merged) SocketPath() string {
	return m.Config.Response.EnforcerSocket
}
