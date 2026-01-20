package detection

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/aniket/zion/config"
	"github.com/aniket/zion/logger"
	"github.com/aniket/zion/response"
)

const (
	PtraceAttach = 16
	PtraceSeize  = 0x4206
)

// PtraceEvent mirrors the kernel-side struct ptrace_event.
type PtraceEvent struct {
	AttackerPID  uint32
	TargetPID    uint32
	AttackerUID  uint32
	Request      uint32
	AttackerComm [64]byte
}

func (e *PtraceEvent) CommString() string {
	n := bytes.IndexByte(e.AttackerComm[:], 0)
	if n == -1 {
		n = len(e.AttackerComm)
	}
	return string(e.AttackerComm[:n])
}

func (e *PtraceEvent) RequestName() string {
	switch e.Request {
	case PtraceAttach:
		return "PTRACE_ATTACH"
	case PtraceSeize:
		return "PTRACE_SEIZE"
	default:
		return fmt.Sprintf("PTRACE_0x%x", e.Request)
	}
}

// getParentPID reads the PPID of a given PID from /proc.
func getParentPID(pid uint32) (uint32, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			var ppid uint32
			fmt.Sscanf(line, "PPid:\t%d", &ppid)
			return ppid, nil
		}
	}
	return 0, fmt.Errorf("PPid not found")
}

// StartInjectionDetector reads ptrace events and applies the detection policy.
// Policy: IF (attacker != parent of target) AND (attacker UID != 0) → CRITICAL
// Blocks forever — run in a goroutine.
func StartInjectionDetector(m *ebpf.Map, cfg *config.Merged, eventLog *logger.Logger) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		log.Fatalf("[ZION] Failed to open ptrace ring buffer: %v", err)
	}

	log.Println("[ZION] Injection detector active — monitoring ptrace calls...")

	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var evt PtraceEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("[ZION] Failed to decode ptrace event: %v", err)
			continue
		}

		// ── Policy evaluation ──────────────────────────────────
		isRoot := evt.AttackerUID == 0

		isParent := false
		if ppid, err := getParentPID(evt.TargetPID); err == nil {
			isParent = (evt.AttackerPID == ppid)
		}

		ts := logger.Timestamp()

		if isRoot {
			// Root ptrace — Treating as CRITICAL for demo visibility (normally INFO)
			eventLog.Log(logger.Event{
				EventType: logger.EventInjection,
				Severity:  logger.SeverityCritical,
				PID:       evt.AttackerPID,
				UID:       evt.AttackerUID,
				Comm:      evt.CommString(),
				Details: map[string]string{
					"target_pid": fmt.Sprintf("%d", evt.TargetPID),
					"request":    evt.RequestName(),
					"verdict":    "root_ptrace_demo",
				},
			})

			fmt.Println()
			fmt.Println("+=========================================================+")
			fmt.Println("|  CRITICAL: PROCESS INJECTION (ROOT) DETECTED            |")
			fmt.Println("+---------------------------------------------------------+")
			fmt.Printf("|  Time:     %-46s|\n", ts)
			fmt.Printf("|  Attacker: %-15s (PID: %-6d, UID: %-5d)   |\n",
				evt.CommString(), evt.AttackerPID, evt.AttackerUID)
			fmt.Printf("|  Target:   PID %-6d                                    |\n",
				evt.TargetPID)
			fmt.Printf("|  Action:   %-15s (Root User)                   |\n",
				evt.RequestName())
			fmt.Println("+=========================================================+")

		} else if isParent {
			// Parent debugging child — probably a debugger
			eventLog.Log(logger.Event{
				EventType: logger.EventInjection,
				Severity:  logger.SeverityWarn,
				PID:       evt.AttackerPID,
				UID:       evt.AttackerUID,
				Comm:      evt.CommString(),
				Details: map[string]string{
					"target_pid": fmt.Sprintf("%d", evt.TargetPID),
					"request":    evt.RequestName(),
					"verdict":    "parent_debug",
				},
			})

			fmt.Printf("\n[%s] [ZION] WARN: Debug attach — %s (PID: %d) → Child PID: %d [%s]\n",
				ts, evt.CommString(), evt.AttackerPID, evt.TargetPID, evt.RequestName())

		} else {
			// Non-parent, non-root → CRITICAL INJECTION
			eventLog.Log(logger.Event{
				EventType: logger.EventInjection,
				Severity:  logger.SeverityCritical,
				PID:       evt.AttackerPID,
				UID:       evt.AttackerUID,
				Comm:      evt.CommString(),
				Details: map[string]string{
					"target_pid": fmt.Sprintf("%d", evt.TargetPID),
					"request":    evt.RequestName(),
					"verdict":    "CRITICAL_injection",
				},
			})

			fmt.Println()
			fmt.Println("+=========================================================+")
			fmt.Println("|  CRITICAL: PROCESS INJECTION DETECTED                    |")
			fmt.Println("+---------------------------------------------------------+")
			fmt.Printf("|  Time:     %-46s|\n", ts)
			fmt.Printf("|  Attacker: %-15s (PID: %-6d, UID: %-5d)   |\n",
				evt.CommString(), evt.AttackerPID, evt.AttackerUID)
			fmt.Printf("|  Target:   PID %-6d                                    |\n",
				evt.TargetPID)
			fmt.Printf("|  Action:   %-15s                               |\n",
				evt.RequestName())
			if cfg.ShouldEnforce() {
				fmt.Println("|  Status:   BLOCKED BY LSM (syscall denied in-kernel)     |")
			}
			fmt.Println("+=========================================================+")

			// AUTO-RESPONSE: dispatch kill order (unless dry-run or LSM enforcing)
			if cfg.ShouldAutoKill() {
				eventLog.Log(logger.Event{
					EventType: logger.EventResponse,
					Severity:  logger.SeverityCritical,
					PID:       evt.AttackerPID,
					UID:       evt.AttackerUID,
					Comm:      evt.CommString(),
					Details: map[string]string{
						"action": "kill_dispatched",
						"reason": "Process injection via " + evt.RequestName(),
					},
				})

				go response.Dispatch(response.KillOrder{
					PID:        evt.AttackerPID,
					Comm:       evt.CommString(),
					Action:     "kill",
					Capture:    cfg.Response.CaptureTraffic,
					Reason:     "Process injection via " + evt.RequestName(),
					SocketPath: cfg.SocketPath(),
				})
			} else if cfg.ShouldEnforce() {
				// LSM already blocked it — no kill needed
				fmt.Printf("[%s] [ZION] LSM blocked ptrace for PID %d (%s) -- no kill needed\n",
					ts, evt.AttackerPID, evt.CommString())
			} else {
				fmt.Printf("[%s] [ZION] dry-run: kill suppressed for PID %d (%s)\n",
					ts, evt.AttackerPID, evt.CommString())
			}
		}
	}
}
