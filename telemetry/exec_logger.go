package telemetry

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/aniket/zion/config"
	"github.com/aniket/zion/logger"
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

// StartExecLogger opens a RingBuffer reader on the given map and logs
// every process execution event. Blocks forever — run in a goroutine.
func StartExecLogger(m *ebpf.Map, cfg *config.Merged, eventLog *logger.Logger) {
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

		// Log to JSON file regardless of whitelist (for forensic completeness)
		severity := logger.SeverityInfo
		if cfg.IsExecWhitelisted(comm) {
			severity = logger.SeverityDebug
		}

		eventLog.Log(logger.Event{
			EventType: logger.EventExec,
			Severity:  severity,
			PID:       evt.PID,
			PPID:      evt.PPID,
			UID:       evt.UID,
			Comm:      comm,
		})

		// Skip console output for whitelisted processes (unless verbose)
		if cfg.IsExecWhitelisted(comm) && !cfg.Verbose {
			continue
		}

		fmt.Printf("[%s] [ZION] Process Started: %s (PID: %d, PPID: %d, UID: %d)\n",
			logger.Timestamp(), comm, evt.PID, evt.PPID, evt.UID)
	}
}
