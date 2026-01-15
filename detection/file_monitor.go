package detection

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/aniket/zion/config"
	"github.com/aniket/zion/logger"
	"github.com/aniket/zion/response"
)

const (
	// Open flags (from Linux headers)
	O_RDONLY = 0x0000
	O_WRONLY = 0x0001
	O_RDWR   = 0x0002
	O_TRUNC  = 0x0200
	O_APPEND = 0x0400
)

// FileEvent mirrors the kernel-side struct file_event.
type FileEvent struct {
	PID      uint32
	UID      uint32
	Flags    uint32
	Pad      uint32
	Comm     [64]byte
	Filename [64]byte
}

func (e *FileEvent) CommString() string {
	n := bytes.IndexByte(e.Comm[:], 0)
	if n == -1 {
		n = len(e.Comm)
	}
	return string(e.Comm[:n])
}

func (e *FileEvent) FilenameString() string {
	n := bytes.IndexByte(e.Filename[:], 0)
	if n == -1 {
		n = len(e.Filename)
	}
	return string(e.Filename[:n])
}

func (e *FileEvent) IsWrite() bool {
	return (e.Flags&O_WRONLY) != 0 || (e.Flags&O_RDWR) != 0
}

func (e *FileEvent) IsTruncate() bool {
	return (e.Flags & O_TRUNC) != 0
}

// ── Sensitive file categories ─────────────────────────────────────

// Credential files — unauthorized reads are T1003.008
var credentialFiles = []string{
	"/etc/shadow",
	"/etc/gshadow",
}

// Files that indicate credential dumping when accessed
var credentialDumpPaths = []string{
	"/maps", // /proc/*/maps
	"/mem",  // /proc/*/mem
}

// Log files — writes/truncation is T1070.002
var logFiles = []string{
	"/var/log/auth.log",
	"/var/log/syslog",
	"/var/log/kern.log",
	"/var/log/messages",
	"/var/log/secure",
	"/var/log/wtmp",
	"/var/log/btmp",
}

// History files — truncation/deletion is T1070.003
var historyFiles = []string{
	".bash_history",
	".zsh_history",
	".python_history",
	".mysql_history",
}

// Persistence targets — writes are T1053.003 / T1546
var persistenceFiles = []string{
	"/etc/crontab",
	"/etc/cron.d/",
	"/etc/cron.daily/",
	"/etc/cron.hourly/",
	"/var/spool/cron/",
	".bashrc",
	".profile",
	".bash_profile",
	".zshrc",
}

// classifyFileAccess determines the detection category and severity.
func classifyFileAccess(filename string, isWrite bool, isTruncate bool) (string, string, string) {
	// Returns: (detection_type, mitre_id, severity)

	// Check credential files (reads are suspicious)
	for _, f := range credentialFiles {
		if strings.Contains(filename, f) {
			return "CREDENTIAL ACCESS", "T1003.008", logger.SeverityCritical
		}
	}

	// Check /proc/*/maps or /proc/*/mem
	for _, suffix := range credentialDumpPaths {
		if strings.HasPrefix(filename, "/proc/") && strings.HasSuffix(filename, suffix) {
			return "CREDENTIAL DUMPING", "T1003", logger.SeverityCritical
		}
	}

	// Check history files (truncation = defense evasion)
	for _, f := range historyFiles {
		if strings.Contains(filename, f) {
			if isWrite || isTruncate {
				return "LOG TAMPERING", "T1070.003", logger.SeverityCritical
			}
			return "HISTORY ACCESS", "T1070.003", logger.SeverityInfo
		}
	}

	// Check log files (writes = defense evasion)
	for _, f := range logFiles {
		if strings.HasPrefix(filename, f) {
			if isWrite || isTruncate {
				return "LOG TAMPERING", "T1070.002", logger.SeverityCritical
			}
			return "LOG ACCESS", "T1070.002", logger.SeverityInfo
		}
	}

	// Check persistence targets (writes are suspicious)
	for _, f := range persistenceFiles {
		if strings.Contains(filename, f) {
			if isWrite {
				return "PERSISTENCE", "T1053.003", logger.SeverityCritical
			}
			return "PERSISTENCE TARGET READ", "T1053.003", logger.SeverityInfo
		}
	}

	return "FILE ACCESS", "", logger.SeverityInfo
}

// StartFileMonitor reads openat events and detects credential access,
// defense evasion, and persistence attempts.
// Blocks forever — run in a goroutine.
func StartFileMonitor(m *ebpf.Map, cfg *config.Merged, eventLog *logger.Logger) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		log.Fatalf("[ZION] Failed to open file event ring buffer: %v", err)
	}

	log.Println("[ZION] File monitor active — watching sensitive file access...")

	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var evt FileEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("[ZION] Failed to decode file event: %v", err)
			continue
		}

		comm := evt.CommString()
		filename := evt.FilenameString()
		ts := logger.Timestamp()

		// Skip whitelisted processes
		if cfg.IsCredentialReader(comm) && strings.Contains(filename, "/etc/shadow") {
			if cfg.Verbose {
				fmt.Printf("[%s] [ZION] DEBUG: Allowed credential read by %s → %s\n",
					ts, comm, filename)
			}
			continue
		}
		if cfg.IsLogWriter(comm) && strings.HasPrefix(filename, "/var/log/") {
			continue
		}
		if cfg.IsPersistenceWriter(comm) {
			continue
		}

		// Whitelist for /proc/*/maps and /mem (Credential Dumping false positives)
		// Chrome, VS Code, Python, Antigravity often read maps/mem for JIT/debugging
		if strings.HasPrefix(filename, "/proc/") &&
			(strings.HasSuffix(filename, "/maps") || strings.HasSuffix(filename, "/mem")) {
			if comm == "chrome" || comm == "chrome_crashpad" || comm == "antigravity" ||
				comm == "code" || comm == "node" || comm == "python3" || comm == "python" || comm == "electron" ||
				comm == "snap" || comm == "snap-seccomp" || comm == "snap-confine" || comm == "snap-exec" || comm == "go" ||
				comm == "MemoryInfra" || comm == "php8.4" || comm == "php" || comm == "sessionclean" {
				continue
			}
		}

		// Classify the file access
		detectionType, mitreID, severity := classifyFileAccess(filename, evt.IsWrite(), evt.IsTruncate())

		// Log to JSON
		eventLog.Log(logger.Event{
			EventType: logger.EventExec, // file event
			Severity:  severity,
			PID:       evt.PID,
			UID:       evt.UID,
			Comm:      comm,
			Details: map[string]string{
				"filename":       filename,
				"flags":          fmt.Sprintf("0x%x", evt.Flags),
				"is_write":       fmt.Sprintf("%v", evt.IsWrite()),
				"detection_type": detectionType,
				"mitre":          mitreID,
			},
		})

		if severity == logger.SeverityCritical {
			fmt.Println()
			fmt.Println("╔═══════════════════════════════════════════════════════════╗")
			fmt.Printf("║  🔴 CRITICAL: %-43s║\n",
				fmt.Sprintf("%s DETECTED (%s)", detectionType, mitreID))
			fmt.Println("╠═══════════════════════════════════════════════════════════╣")
			fmt.Printf("║  Time:     %-46s║\n", ts)
			fmt.Printf("║  Process:  %-15s (PID: %-6d, UID: %-5d)   ║\n",
				comm, evt.PID, evt.UID)
			fmt.Printf("║  File:     %-46s║\n", truncateStr(filename, 46))
			if evt.IsWrite() {
				fmt.Println("║  Access:   WRITE                                         ║")
			} else {
				fmt.Println("║  Access:   READ                                          ║")
			}
			fmt.Println("╚═══════════════════════════════════════════════════════════╝")

			// Auto-kill for credential access and log tampering
			if cfg.ShouldAutoKill() && (detectionType == "CREDENTIAL ACCESS" ||
				detectionType == "CREDENTIAL DUMPING" ||
				detectionType == "LOG TAMPERING") {

				eventLog.Log(logger.Event{
					EventType: logger.EventResponse,
					Severity:  logger.SeverityCritical,
					PID:       evt.PID,
					Comm:      comm,
					Details: map[string]string{
						"action": "kill_dispatched",
						"reason": fmt.Sprintf("%s: %s", detectionType, filename),
					},
				})

				go response.Dispatch(response.KillOrder{
					PID:        evt.PID,
					Comm:       comm,
					Action:     "kill",
					Capture:    cfg.Response.CaptureTraffic,
					Reason:     fmt.Sprintf("%s: %s", detectionType, filename),
					SocketPath: cfg.SocketPath(),
				})
			} else if cfg.ShouldEnforce() {
				fmt.Printf("[%s] [ZION] 🛡️  LSM blocked file access for PID %d (%s) — no kill needed\n",
					ts, evt.PID, comm)
			} else if !cfg.ShouldAutoKill() {
				fmt.Printf("[%s] [ZION] ⏸️  Dry-run: kill suppressed for PID %d (%s)\n",
					ts, evt.PID, comm)
			}
		} else if severity == logger.SeverityWarn {
			fmt.Printf("\n[%s] [ZION] WARN: %s — %s (PID: %d) → %s\n",
				ts, detectionType, comm, evt.PID, filename)
		}
	}
}

// truncateStr truncates a string to maxLen with ellipsis.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
