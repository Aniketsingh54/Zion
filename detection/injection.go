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
func StartInjectionDetector(m *ebpf.Map) {
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

		if isRoot {
			// Root ptrace — log as INFO, not an alert
			fmt.Printf("\n[ZION] INFO: Root ptrace — %s (PID: %d) → Target PID: %d [%s]\n",
				evt.CommString(), evt.AttackerPID, evt.TargetPID, evt.RequestName())
		} else if isParent {
			// Parent debugging child — probably a debugger
			fmt.Printf("\n[ZION] WARN: Debug attach — %s (PID: %d) → Child PID: %d [%s]\n",
				evt.CommString(), evt.AttackerPID, evt.TargetPID, evt.RequestName())
		} else {
			// Non-parent, non-root → CRITICAL INJECTION
			fmt.Println()
			fmt.Println("╔═══════════════════════════════════════════════════════════╗")
			fmt.Println("║  ⚠️  CRITICAL: PROCESS INJECTION DETECTED                ║")
			fmt.Println("╠═══════════════════════════════════════════════════════════╣")
			fmt.Printf("║  Attacker: %-15s (PID: %-6d, UID: %-5d)   ║\n",
				evt.CommString(), evt.AttackerPID, evt.AttackerUID)
			fmt.Printf("║  Target:   PID %-6d                                    ║\n",
				evt.TargetPID)
			fmt.Printf("║  Action:   %-15s                               ║\n",
				evt.RequestName())
			fmt.Println("╚═══════════════════════════════════════════════════════════╝")

			// AUTO-RESPONSE: dispatch kill order
			go response.Dispatch(response.KillOrder{
				PID:     evt.AttackerPID,
				Comm:    evt.CommString(),
				Action:  "kill",
				Capture: true,
				Reason:  "Process injection via " + evt.RequestName(),
			})
		}
	}
}
