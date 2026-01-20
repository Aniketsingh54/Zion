package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Severity levels for events.
const (
	SeverityDebug    = "DEBUG"
	SeverityInfo     = "INFO"
	SeverityWarn     = "WARN"
	SeverityCritical = "CRITICAL"
)

// Event types.
const (
	EventExec      = "exec"
	EventInjection = "injection"
	EventPrivEsc   = "privilege_escalation"
	EventResponse  = "response"
)

// Event is a structured log entry written to the JSON log file.
type Event struct {
	Timestamp string            `json:"timestamp"`
	EventType string            `json:"event_type"`
	Severity  string            `json:"severity"`
	PID       uint32            `json:"pid"`
	PPID      uint32            `json:"ppid,omitempty"`
	UID       uint32            `json:"uid"`
	Comm      string            `json:"comm"`
	Details   map[string]string `json:"details,omitempty"`
}

// Stats tracks event counts for the shutdown summary.
type Stats struct {
	ExecEvents      atomic.Int64
	InjectionWarn   atomic.Int64
	InjectionCrit   atomic.Int64
	PrivEscInfo     atomic.Int64
	PrivEscCrit     atomic.Int64
	KillsDispatched atomic.Int64
	StartTime       time.Time
}

// Logger writes structured JSON events to a log file.
type Logger struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
	Stats   Stats
}

// New creates a logger that writes to a timestamped file in the given directory.
// Returns nil (no-op) if enabled is false.
func New(dir string, enabled bool) (*Logger, error) {
	if !enabled {
		return &Logger{Stats: Stats{StartTime: time.Now()}}, nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", dir, err)
	}

	filename := fmt.Sprintf("zion_%s.json", time.Now().Format("2006-01-02_15-04-05"))
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create log file %s: %w", path, err)
	}

	fmt.Printf("[ZION] Event log: %s\n", path)

	return &Logger{
		file:    f,
		encoder: json.NewEncoder(f),
		Stats:   Stats{StartTime: time.Now()},
	}, nil
}

// Log writes a structured event to the JSON log file and updates stats.
func (l *Logger) Log(evt Event) {
	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().Format(time.RFC3339)
	}

	// Update stats
	switch evt.EventType {
	case EventExec:
		l.Stats.ExecEvents.Add(1)
	case EventInjection:
		if evt.Severity == SeverityCritical {
			l.Stats.InjectionCrit.Add(1)
		} else {
			l.Stats.InjectionWarn.Add(1)
		}
	case EventPrivEsc:
		if evt.Severity == SeverityCritical {
			l.Stats.PrivEscCrit.Add(1)
		} else {
			l.Stats.PrivEscInfo.Add(1)
		}
	case EventResponse:
		l.Stats.KillsDispatched.Add(1)
	}

	// Write to file if enabled
	if l.file == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.encoder.Encode(evt)
}

// Close flushes and closes the log file.
func (l *Logger) Close() {
	if l.file != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.file.Sync()
		l.file.Close()
	}
}

// PrintStats prints a summary table of all events observed.
func (l *Logger) PrintStats() {
	elapsed := time.Since(l.Stats.StartTime).Round(time.Second)

	fmt.Println()
	fmt.Println("+=============================================+")
	fmt.Println("|           ZION SESSION SUMMARY              |")
	fmt.Println("+---------------------------------------------+")
	fmt.Printf("|  Duration:           %-24s|\n", elapsed)
	fmt.Printf("|  Exec events:        %-24d|\n", l.Stats.ExecEvents.Load())
	fmt.Printf("|  Injection warnings: %-24d|\n", l.Stats.InjectionWarn.Load())
	fmt.Printf("|  Injection CRITICAL: %-24d|\n", l.Stats.InjectionCrit.Load())
	fmt.Printf("|  Priv esc (expected):%-24d|\n", l.Stats.PrivEscInfo.Load())
	fmt.Printf("|  Priv esc CRITICAL:  %-24d|\n", l.Stats.PrivEscCrit.Load())
	fmt.Printf("|  Kills dispatched:   %-24d|\n", l.Stats.KillsDispatched.Load())
	fmt.Println("+=============================================+")
}

// Timestamp returns a formatted timestamp string for console output.
func Timestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}
