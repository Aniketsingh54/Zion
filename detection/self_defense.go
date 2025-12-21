package detection

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/aniket/zion/config"
	"github.com/aniket/zion/logger"
	"github.com/aniket/zion/response"
)

// KillEvent mirrors the kernel-side struct kill_event.
type KillEvent struct {
	CallerPID uint32
	CallerUID uint32
	TargetPID int32
	Signal    int32
	Comm      [64]byte
}

func (e *KillEvent) CommString() string {
	n := bytes.IndexByte(e.Comm[:], 0)
	if n == -1 {
		n = len(e.Comm)
	}
	return string(e.Comm[:n])
}

func (e *KillEvent) SignalName() string {
	switch e.Signal {
	case 9:
		return "SIGKILL"
	case 15:
		return "SIGTERM"
	case 19:
		return "SIGSTOP"
	default:
		return fmt.Sprintf("SIG(%d)", e.Signal)
	}
}

// StartSelfDefenseDetector monitors for attempts to kill or stop
// the Zion process itself. This detects sensor tampering (T1562).
// Blocks forever — run in a goroutine.
func StartSelfDefenseDetector(m *ebpf.Map, cfg *config.Merged, eventLog *logger.Logger) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		log.Fatalf("[ZION] Failed to open kill event ring buffer: %v", err)
	}

	log.Println("[ZION] Self-defense detector active — protecting Zion process...")

	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var evt KillEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("[ZION] Failed to decode kill event: %v", err)
			continue
		}

		comm := evt.CommString()
		ts := logger.Timestamp()

		// CRITICAL: Someone is trying to kill Zion
		eventLog.Log(logger.Event{
			EventType: logger.EventInjection,
			Severity:  logger.SeverityCritical,
			PID:       evt.CallerPID,
			UID:       evt.CallerUID,
			Comm:      comm,
			Details: map[string]string{
				"target_pid":     fmt.Sprintf("%d", evt.TargetPID),
				"signal":         evt.SignalName(),
				"detection_type": "SENSOR_TAMPERING",
				"mitre":          "T1562",
			},
		})

		fmt.Println()
		fmt.Println("╔═══════════════════════════════════════════════════════════╗")
		fmt.Println("║  🛡️  CRITICAL: SENSOR TAMPERING DETECTED (T1562)         ║")
		fmt.Println("╠═══════════════════════════════════════════════════════════╣")
		fmt.Printf("║  Time:     %-46s║\n", ts)
		fmt.Printf("║  Attacker: %-15s (PID: %-6d, UID: %-5d)   ║\n",
			comm, evt.CallerPID, evt.CallerUID)
		fmt.Printf("║  Signal:   %-15s → Zion (PID: %-6d)        ║\n",
			evt.SignalName(), evt.TargetPID)
		fmt.Println("║  Status:   ATTEMPT TO DISABLE SECURITY SENSOR            ║")
		fmt.Println("╚═══════════════════════════════════════════════════════════╝")

		// Auto-kill the attacker trying to kill us
		if cfg.ShouldAutoKill() {
			eventLog.Log(logger.Event{
				EventType: logger.EventResponse,
				Severity:  logger.SeverityCritical,
				PID:       evt.CallerPID,
				Comm:      comm,
				Details: map[string]string{
					"action": "kill_dispatched",
					"reason": fmt.Sprintf("Attempted %s on Zion PID %d", evt.SignalName(), evt.TargetPID),
				},
			})

			go response.Dispatch(response.KillOrder{
				PID:        evt.CallerPID,
				Comm:       comm,
				Action:     "kill",
				Capture:    cfg.Response.CaptureTraffic,
				Reason:     fmt.Sprintf("Sensor tampering: %s on Zion", evt.SignalName()),
				SocketPath: cfg.SocketPath(),
			})
		} else {
			fmt.Printf("[%s] [ZION] ⏸️  Dry-run: kill suppressed for PID %d (%s)\n",
				ts, evt.CallerPID, comm)
		}
	}
}

// Dup2Event mirrors the kernel-side struct dup2_event.
type Dup2Event struct {
	PID   uint32
	UID   uint32
	OldFD uint32
	NewFD uint32
	Comm  [64]byte
}

func (e *Dup2Event) CommString() string {
	n := bytes.IndexByte(e.Comm[:], 0)
	if n == -1 {
		n = len(e.Comm)
	}
	return string(e.Comm[:n])
}

func (e *Dup2Event) FDName() string {
	switch e.NewFD {
	case 0:
		return "STDIN"
	case 1:
		return "STDOUT"
	case 2:
		return "STDERR"
	default:
		return fmt.Sprintf("fd(%d)", e.NewFD)
	}
}

// StartDup2Detector monitors dup2 calls by shell processes to detect
// file descriptor redirection into network sockets (reverse shell pattern).
// Blocks forever — run in a goroutine.
func StartDup2Detector(m *ebpf.Map, cfg *config.Merged, eventLog *logger.Logger) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		log.Fatalf("[ZION] Failed to open dup2 event ring buffer: %v", err)
	}

	log.Println("[ZION] FD redirection detector active — monitoring dup2 calls...")

	// Track how many fd redirections each PID has done (stdin+stdout+stderr = reverse shell)
	pidRedirects := make(map[uint32]uint32)

	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var evt Dup2Event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("[ZION] Failed to decode dup2 event: %v", err)
			continue
		}

		comm := evt.CommString()
		ts := logger.Timestamp()

		// Only suspicious if it's a shell process
		if !shellComms[comm] {
			continue
		}

		// Track fd redirections per PID
		pidRedirects[evt.PID]++
		count := pidRedirects[evt.PID]

		eventLog.Log(logger.Event{
			EventType: logger.EventInjection,
			Severity:  logger.SeverityWarn,
			PID:       evt.PID,
			UID:       evt.UID,
			Comm:      comm,
			Details: map[string]string{
				"old_fd":    fmt.Sprintf("%d", evt.OldFD),
				"new_fd":    evt.FDName(),
				"redirects": fmt.Sprintf("%d", count),
				"mitre":     "T1059.004",
			},
		})

		// If a shell redirects 2+ standard fds → very likely reverse shell
		if count >= 2 {
			fmt.Println()
			fmt.Println("╔═══════════════════════════════════════════════════════════╗")
			fmt.Println("║  🔴 CRITICAL: REVERSE SHELL FD REDIRECT (T1059.004)      ║")
			fmt.Println("╠═══════════════════════════════════════════════════════════╣")
			fmt.Printf("║  Time:     %-46s║\n", ts)
			fmt.Printf("║  Shell:    %-15s (PID: %-6d, UID: %-5d)   ║\n",
				comm, evt.PID, evt.UID)
			fmt.Printf("║  Action:   dup2(fd %d → %s)                              ║\n",
				evt.OldFD, evt.FDName())
			fmt.Printf("║  FD Redirects: %d (stdin/stdout/stderr → socket)       ║\n", count)
			fmt.Println("╚═══════════════════════════════════════════════════════════╝")

			if cfg.ShouldAutoKill() {
				eventLog.Log(logger.Event{
					EventType: logger.EventResponse,
					Severity:  logger.SeverityCritical,
					PID:       evt.PID,
					Comm:      comm,
					Details: map[string]string{
						"action": "kill_dispatched",
						"reason": "Reverse shell fd redirection",
					},
				})

				go response.Dispatch(response.KillOrder{
					PID:        evt.PID,
					Comm:       comm,
					Action:     "kill",
					Capture:    cfg.Response.CaptureTraffic,
					Reason:     "Reverse shell fd redirection (dup2 pattern)",
					SocketPath: cfg.SocketPath(),
				})

				// Reset counter after killing
				delete(pidRedirects, evt.PID)
			} else {
				fmt.Printf("[%s] [ZION] ⏸️  Dry-run: kill suppressed for PID %d (%s)\n",
					ts, evt.PID, comm)
			}
		} else {
			fmt.Printf("\n[%s] [ZION] WARN: Shell FD redirect — %s (PID: %d) dup2(fd %d → %s)\n",
				ts, comm, evt.PID, evt.OldFD, evt.FDName())
		}
	}
}
