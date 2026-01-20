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

// MemfdEvent mirrors the kernel-side struct memfd_event.
type MemfdEvent struct {
	PID   uint32
	UID   uint32
	Flags uint32
	Pad   uint32
	Comm  [64]byte
	Name  [64]byte
}

func (e *MemfdEvent) CommString() string {
	n := bytes.IndexByte(e.Comm[:], 0)
	if n == -1 {
		n = len(e.Comm)
	}
	return string(e.Comm[:n])
}

func (e *MemfdEvent) NameString() string {
	n := bytes.IndexByte(e.Name[:], 0)
	if n == -1 {
		n = len(e.Name)
	}
	return string(e.Name[:n])
}

// Legitimate uses of memfd_create (e.g., display servers, browsers).
var allowedMemfdUsers = map[string]bool{
	"Xorg":            true,
	"Xwayland":        true,
	"pulseaudio":      true,
	"pipewire":        true,
	"pipewire-pulse":  true,
	"wireplumber":     true,
	"gnome-shell":     true,
	"gdm":             true,
	"systemd":         true,
	"chrome":          true,
	"chrome_crashpad": true,
	"antigravity":     true,
	"antigravit:gl0":  true,
	"code":            true, // VS Code
	"node":            true,
	"python3":         true,
	"python":          true,
	"electron":        true,
	"cinnamon":        true, // Desktop environment
	"nautilus":        true, // File manager
}

// StartFilelessDetector monitors memfd_create calls to detect
// fileless malware that executes code directly from RAM.
// MITRE ATT&CK: T1620 (Reflective Code Loading)
// Blocks forever — run in a goroutine.
func StartFilelessDetector(m *ebpf.Map, cfg *config.Merged, eventLog *logger.Logger) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		log.Fatalf("[ZION] Failed to open memfd event ring buffer: %v", err)
	}

	log.Println("[ZION] Fileless malware detector active — monitoring memfd_create...")

	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var evt MemfdEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("[ZION] Failed to decode memfd event: %v", err)
			continue
		}

		comm := evt.CommString()
		name := evt.NameString()
		ts := logger.Timestamp()

		// Skip known legitimate memfd users
		if allowedMemfdUsers[comm] {
			if cfg.Verbose {
				fmt.Printf("[%s] [ZION] DEBUG: Allowed memfd_create by %s (name: %s)\n",
					ts, comm, name)
			}
			continue
		}

		// Any non-whitelisted memfd_create is suspicious → CRITICAL
		eventLog.Log(logger.Event{
			EventType: logger.EventExec,
			Severity:  logger.SeverityCritical,
			PID:       evt.PID,
			UID:       evt.UID,
			Comm:      comm,
			Details: map[string]string{
				"memfd_name":     name,
				"flags":          fmt.Sprintf("0x%x", evt.Flags),
				"detection_type": "FILELESS_EXECUTION",
				"mitre":          "T1620",
			},
		})

		fmt.Println()
		fmt.Println("+=========================================================+")
		fmt.Println("|  CRITICAL: FILELESS EXECUTION DETECTED (T1620)           |")
		fmt.Println("+---------------------------------------------------------+")
		fmt.Printf("|  Time:     %-46s|\n", ts)
		fmt.Printf("|  Process:  %-15s (PID: %-6d, UID: %-5d)   |\n",
			comm, evt.PID, evt.UID)
		fmt.Printf("|  MemFD:    %-46s|\n", name)
		fmt.Println("|  Status:   IN-MEMORY CODE LOADING (NO DISK FILE)         |")
		fmt.Println("+=========================================================+")

		if cfg.ShouldAutoKill() {
			eventLog.Log(logger.Event{
				EventType: logger.EventResponse,
				Severity:  logger.SeverityCritical,
				PID:       evt.PID,
				Comm:      comm,
				Details: map[string]string{
					"action": "kill_dispatched",
					"reason": fmt.Sprintf("Fileless execution via memfd_create(%s)", name),
				},
			})

			go response.Dispatch(response.KillOrder{
				PID:        evt.PID,
				Comm:       comm,
				Action:     "kill",
				Capture:    cfg.Response.CaptureTraffic,
				Reason:     fmt.Sprintf("Fileless execution via memfd_create(%s)", name),
				SocketPath: cfg.SocketPath(),
			})
		} else if cfg.ShouldEnforce() {
			fmt.Printf("[%s] [ZION] LSM blocked memfd_create for PID %d (%s) -- no kill needed\n",
				ts, evt.PID, comm)
		} else {
			fmt.Printf("[%s] [ZION] dry-run: kill suppressed for PID %d (%s)\n",
				ts, evt.PID, comm)
		}
	}
}
