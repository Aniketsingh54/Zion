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

// ConnectEvent mirrors the kernel-side struct connect_event.
type ConnectEvent struct {
	PID    uint32
	UID    uint32
	Port   uint16
	Family uint16
	DstIP4 uint32
	Comm   [64]byte
}

func (e *ConnectEvent) CommString() string {
	n := bytes.IndexByte(e.Comm[:], 0)
	if n == -1 {
		n = len(e.Comm)
	}
	return string(e.Comm[:n])
}

// FormatIP converts a uint32 IP (network byte order) to dotted notation.
func (e *ConnectEvent) FormatIP() string {
	ip := e.DstIP4
	return fmt.Sprintf("%d.%d.%d.%d",
		ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF)
}

// Known reverse shell tools and suspicious shell invocations.
var reverseShellComms = map[string]bool{
	"nc":         true,
	"ncat":       true,
	"netcat":     true,
	"socat":      true,
	"nmap":       true,
	"msfconsole": true,
	"msfvenom":   true,
}

// Shell processes that shouldn't be making outbound connections.
var shellComms = map[string]bool{
	"bash": true,
	"sh":   true,
	"zsh":  true,
	"dash": true,
	"fish": true,
	"ksh":  true,
}

// Suspicious ports commonly used for reverse shells.
var suspiciousPorts = map[uint16]bool{
	4444: true, // meterpreter default
	4445: true,
	5555: true,
	6666: true,
	8888: true,
	1337: true,
	9001: true,
	9090: true,
	1234: true,
}

// IsReverseShellComm checks exec events for known reverse shell patterns.
// Called from exec_logger as an additional analysis layer.
func IsReverseShellComm(comm string) bool {
	comm = strings.ToLower(comm)
	return reverseShellComms[comm]
}

// StartReverseShellDetector monitors outbound connections for reverse shell patterns.
// Policy: (shell process making outbound connection) OR (connection to suspicious port) → CRITICAL
// Blocks forever — run in a goroutine.
func StartReverseShellDetector(m *ebpf.Map, cfg *config.Merged, eventLog *logger.Logger) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		log.Fatalf("[ZION] Failed to open connect ring buffer: %v", err)
	}

	log.Println("[ZION] Reverse shell detector active — monitoring outbound connections...")

	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var evt ConnectEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("[ZION] Failed to decode connect event: %v", err)
			continue
		}

		comm := evt.CommString()
		ts := logger.Timestamp()
		dstIP := evt.FormatIP()

		// ── Detection Logic ──────────────────────────────────
		isShell := shellComms[comm]
		isSuspiciousPort := suspiciousPorts[evt.Port]
		isReverseShellTool := reverseShellComms[comm]
		isLoopback := (evt.DstIP4 & 0xFF) == 127

		severity := logger.SeverityInfo

		if isReverseShellTool {
			// Known reverse shell tool making connection → CRITICAL
			severity = logger.SeverityCritical
		} else if isShell && !isLoopback {
			// Shell process connecting outbound → CRITICAL
			severity = logger.SeverityCritical
		} else if isSuspiciousPort && !isLoopback {
			// Any process connecting to a suspicious port → WARN
			severity = logger.SeverityWarn
		}

		// Log all connection events
		eventLog.Log(logger.Event{
			EventType: logger.EventInjection, // Reusing for now
			Severity:  severity,
			PID:       evt.PID,
			UID:       evt.UID,
			Comm:      comm,
			Details: map[string]string{
				"dst_ip":   dstIP,
				"dst_port": fmt.Sprintf("%d", evt.Port),
				"verdict":  severity,
				"is_shell": fmt.Sprintf("%v", isShell),
				"mitre":    "T1059.004",
			},
		})

		if severity == logger.SeverityCritical {
			fmt.Println()
			fmt.Println("╔═══════════════════════════════════════════════════════════╗")
			fmt.Println("║  🔴 CRITICAL: REVERSE SHELL DETECTED (T1059.004)         ║")
			fmt.Println("╠═══════════════════════════════════════════════════════════╣")
			fmt.Printf("║  Time:     %-46s║\n", ts)
			fmt.Printf("║  Process:  %-15s (PID: %-6d, UID: %-5d)   ║\n",
				comm, evt.PID, evt.UID)
			fmt.Printf("║  Target:   %s:%-6d                                 ║\n",
				dstIP, evt.Port)
			fmt.Println("║  Status:   OUTBOUND SHELL CONNECTION                     ║")
			fmt.Println("╚═══════════════════════════════════════════════════════════╝")

			if cfg.ShouldAutoKill() {
				eventLog.Log(logger.Event{
					EventType: logger.EventResponse,
					Severity:  logger.SeverityCritical,
					PID:       evt.PID,
					Comm:      comm,
					Details: map[string]string{
						"action": "kill_dispatched",
						"reason": fmt.Sprintf("Reverse shell to %s:%d", dstIP, evt.Port),
					},
				})

				go response.Dispatch(response.KillOrder{
					PID:        evt.PID,
					Comm:       comm,
					Action:     "kill",
					Capture:    cfg.Response.CaptureTraffic,
					Reason:     fmt.Sprintf("Reverse shell to %s:%d", dstIP, evt.Port),
					SocketPath: cfg.SocketPath(),
				})
			} else {
				fmt.Printf("[%s] [ZION] ⏸️  Dry-run: kill suppressed for PID %d (%s)\n",
					ts, evt.PID, comm)
			}
		} else if severity == logger.SeverityWarn {
			fmt.Printf("\n[%s] [ZION] WARN: Suspicious connection — %s (PID: %d) → %s:%d\n",
				ts, comm, evt.PID, dstIP, evt.Port)
		}
	}
}
