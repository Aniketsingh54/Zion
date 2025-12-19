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

// PrivEvent mirrors the kernel-side struct priv_event.
type PrivEvent struct {
	PID    uint32
	OldUID uint32
	NewUID uint32
	Pad    uint32
	Comm   [64]byte
}

func (e *PrivEvent) CommString() string {
	n := bytes.IndexByte(e.Comm[:], 0)
	if n == -1 {
		n = len(e.Comm)
	}
	return string(e.Comm[:n])
}

// StartPrivilegeDetector reads setuid events and flags unexpected
// privilege escalation to root. Blocks forever — run in a goroutine.
func StartPrivilegeDetector(m *ebpf.Map, cfg *config.Merged, eventLog *logger.Logger) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		log.Fatalf("[ZION] Failed to open privilege ring buffer: %v", err)
	}

	log.Println("[ZION] Privilege escalation detector active...")

	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var evt PrivEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("[ZION] Failed to decode priv event: %v", err)
			continue
		}

		comm := evt.CommString()
		ts := logger.Timestamp()

		if cfg.IsEscalationAllowed(comm) {
			// Expected escalation — log as INFO
			eventLog.Log(logger.Event{
				EventType: logger.EventPrivEsc,
				Severity:  logger.SeverityInfo,
				PID:       evt.PID,
				UID:       evt.OldUID,
				Comm:      comm,
				Details: map[string]string{
					"old_uid": fmt.Sprintf("%d", evt.OldUID),
					"new_uid": fmt.Sprintf("%d", evt.NewUID),
					"verdict": "expected_escalation",
				},
			})

			fmt.Printf("[%s] [ZION] INFO: Expected privilege transition: %s (PID: %d) UID %d → %d\n",
				ts, comm, evt.PID, evt.OldUID, evt.NewUID)

		} else {
			// Unexpected escalation — CRITICAL ALERT
			eventLog.Log(logger.Event{
				EventType: logger.EventPrivEsc,
				Severity:  logger.SeverityCritical,
				PID:       evt.PID,
				UID:       evt.OldUID,
				Comm:      comm,
				Details: map[string]string{
					"old_uid": fmt.Sprintf("%d", evt.OldUID),
					"new_uid": fmt.Sprintf("%d", evt.NewUID),
					"verdict": "CRITICAL_unauthorized",
				},
			})

			fmt.Println()
			fmt.Println("╔═══════════════════════════════════════════════════════════╗")
			fmt.Println("║  🔴 CRITICAL: PRIVILEGE ESCALATION DETECTED (T1068)      ║")
			fmt.Println("╠═══════════════════════════════════════════════════════════╣")
			fmt.Printf("║  Time:     %-46s║\n", ts)
			fmt.Printf("║  Binary:   %-15s (PID: %-6d)                 ║\n",
				comm, evt.PID)
			fmt.Printf("║  UID:      %d → %d (ROOT)                                ║\n",
				evt.OldUID, evt.NewUID)
			fmt.Println("║  Status:   UNAUTHORIZED ELEVATION                        ║")
			fmt.Println("╚═══════════════════════════════════════════════════════════╝")

			// AUTO-RESPONSE: dispatch kill order (unless dry-run)
			if cfg.ShouldAutoKill() {
				eventLog.Log(logger.Event{
					EventType: logger.EventResponse,
					Severity:  logger.SeverityCritical,
					PID:       evt.PID,
					UID:       evt.OldUID,
					Comm:      comm,
					Details: map[string]string{
						"action": "kill_dispatched",
						"reason": fmt.Sprintf("Unauthorized setuid %d → %d", evt.OldUID, evt.NewUID),
					},
				})

				go response.Dispatch(response.KillOrder{
					PID:        evt.PID,
					Comm:       comm,
					Action:     "kill",
					Capture:    cfg.Response.CaptureTraffic,
					Reason:     fmt.Sprintf("Unauthorized setuid %d → %d", evt.OldUID, evt.NewUID),
					SocketPath: cfg.SocketPath(),
				})
			} else {
				fmt.Printf("[%s] [ZION] ⏸️  Dry-run: kill suppressed for PID %d (%s)\n",
					ts, evt.PID, comm)
			}
		}
	}
}
