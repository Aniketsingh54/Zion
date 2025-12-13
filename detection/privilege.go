package detection

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
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

// Legitimate binaries that are expected to escalate to root.
var allowedEscalators = map[string]bool{
	"sudo":        true,
	"su":          true,
	"pkexec":      true,
	"doas":        true,
	"login":       true,
	"sshd":        true,
	"cron":        true,
	"polkitd":     true,
	"newgrp":      true,
	"unix_chkpwd": true,
}

// StartPrivilegeDetector reads setuid events and flags unexpected
// privilege escalation to root. Blocks forever — run in a goroutine.
func StartPrivilegeDetector(m *ebpf.Map) {
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

		if allowedEscalators[comm] {
			// Expected escalation — log as INFO
			fmt.Printf("[ZION] INFO: Expected privilege transition: %s (PID: %d) UID %d → %d\n",
				comm, evt.PID, evt.OldUID, evt.NewUID)
		} else {
			// Unexpected escalation — CRITICAL ALERT
			fmt.Println()
			fmt.Println("╔═══════════════════════════════════════════════════════════╗")
			fmt.Println("║  🔴 CRITICAL: PRIVILEGE ESCALATION DETECTED (T1068)      ║")
			fmt.Println("╠═══════════════════════════════════════════════════════════╣")
			fmt.Printf("║  Binary:   %-15s (PID: %-6d)                 ║\n",
				comm, evt.PID)
			fmt.Printf("║  UID:      %d → %d (ROOT)                                ║\n",
				evt.OldUID, evt.NewUID)
			fmt.Println("║  Status:   UNAUTHORIZED ELEVATION                        ║")
			fmt.Println("╚═══════════════════════════════════════════════════════════╝")
		}
	}
}
