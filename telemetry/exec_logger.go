package telemetry

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// ExecEvent mirrors the kernel-side struct exec_event.
// Field order and sizes must match exactly.
type ExecEvent struct {
	PID  uint32
	PPID uint32
	UID  uint32
	Comm [64]byte
}

// CommString returns the command name as a clean Go string.
func (e *ExecEvent) CommString() string {
	// Trim null bytes from the fixed-size array
	n := bytes.IndexByte(e.Comm[:], 0)
	if n == -1 {
		n = len(e.Comm)
	}
	return string(e.Comm[:n])
}

// Noisy processes spawned by shell prompts and status bars — filter out.
var ignoreComms = map[string]bool{
	// Shell prompt (zsh/powerline)
	"ip": true, "cut": true, "head": true, "hostname": true,
	"uname": true, "sed": true, "awk": true, "grep": true,
	"tr": true, "wc": true, "tput": true, "dircolors": true,
	"sh": true, "cat": true, "sleep": true,
	// Status bar / system monitors
	"which": true, "ps": true, "cpuUsage.sh": true,
	// IDE / tooling background
	"git": true, "getent": true,
}

// StartExecLogger opens a RingBuffer reader on the given map and logs
// every process execution event. Blocks forever — run in a goroutine.
func StartExecLogger(m *ebpf.Map) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		log.Fatalf("[ZION] Failed to open ring buffer reader: %v", err)
	}

	log.Println("[ZION] Exec telemetry active — monitoring process executions...")

	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var evt ExecEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("[ZION] Failed to decode exec event: %v", err)
			continue
		}

		comm := evt.CommString()
		if ignoreComms[comm] {
			continue
		}

		fmt.Printf("[ZION] Process Started: %s (PID: %d, PPID: %d, UID: %d)\n",
			comm, evt.PID, evt.PPID, evt.UID)
	}
}
