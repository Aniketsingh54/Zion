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

// WhitelistConfig holds process whitelists for all detection categories.
type WhitelistConfig struct {
	Exec               []string `yaml:"exec"`
	Escalation         []string `yaml:"escalation"`
	CredentialReaders  []string `yaml:"credential_readers"`
	LogWriters         []string `yaml:"log_writers"`
	PersistenceWriters []string `yaml:"persistence_writers"`
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
	execWhitelist      map[string]bool
	escalationAllowed  map[string]bool
	credentialReaders  map[string]bool
	logWriters         map[string]bool
	persistenceWriters map[string]bool
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
	m.execWhitelist = buildMap(cfg.Whitelist.Exec)
	m.escalationAllowed = buildMap(cfg.Whitelist.Escalation)
	m.credentialReaders = buildMap(cfg.Whitelist.CredentialReaders)
	m.logWriters = buildMap(cfg.Whitelist.LogWriters)
	m.persistenceWriters = buildMap(cfg.Whitelist.PersistenceWriters)

	return m
}

func buildMap(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
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

// IsCredentialReader returns true if the process is allowed to read /etc/shadow etc.
func (m *Merged) IsCredentialReader(comm string) bool {
	return m.credentialReaders[comm]
}

// IsLogWriter returns true if the process is allowed to modify log files.
func (m *Merged) IsLogWriter(comm string) bool {
	return m.logWriters[comm]
}

// IsPersistenceWriter returns true if the process is allowed to modify crontab/rc files.
func (m *Merged) IsPersistenceWriter(comm string) bool {
	return m.persistenceWriters[comm]
}

// ShouldAutoKill returns true if automated response is enabled.
func (m *Merged) ShouldAutoKill() bool {
	return m.Config.Response.AutoKill && !m.NoKill
}

// SocketPath returns the configured enforcer socket path.
func (m *Merged) SocketPath() string {
	return m.Config.Response.EnforcerSocket
}
