package lsm

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip -type policy_flags zionLsm ../ebpf/zion_lsm.c -- -I../headers -O2 -g -target bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/aniket/zion/config"
	"github.com/aniket/zion/logger"
)

// LSMEngine manages loading, attaching, and policy for BPF-LSM programs.
type LSMEngine struct {
	objs  zionLsmObjects
	links []link.Link
}

// LSMEvent mirrors struct zion_lsm_event from ebpf/zion_lsm.c.
type LSMEvent struct {
	Pid      uint32
	Uid      uint32
	Hook     uint32
	Decision int32
	Comm     [64]byte
	Detail   [64]byte
}

// New loads and attaches all BPF-LSM programs.
func New(cfg *config.Merged, eventLog *logger.Logger) (*LSMEngine, error) {
	var objs zionLsmObjects
	if err := loadZionLsmObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load LSM eBPF objects: %w", err)
	}

	engine := &LSMEngine{objs: objs}

	// Set Zion's PID for self-defense hook
	var pidKey uint32
	zionPID := uint32(os.Getpid())
	if err := objs.LsmZionPid.Update(pidKey, zionPID, ebpf.UpdateAny); err != nil {
		log.Printf("[LSM] WARN: failed to set self-defense PID: %v", err)
	}

	if err := engine.loadPolicy(cfg); err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to load LSM policy: %w", err)
	}

	// Attach LSM programs
	lsmPrograms := []struct {
		name string
		prog *ebpf.Program
	}{
		{"ptrace_access_check", objs.LsmPtraceAccessCheck},
		{"task_fix_setuid", objs.LsmTaskFixSetuid},
		{"file_open", objs.LsmFileOpen},
		{"task_kill", objs.LsmTaskKill},
		{"bprm_check_security", objs.LsmBprmCheck},
	}

	for _, p := range lsmPrograms {
		l, err := link.AttachLSM(link.LSMOptions{
			Program: p.prog,
		})
		if err != nil {
			engine.Close()
			return nil, fmt.Errorf("failed to attach LSM/%s: %w", p.name, err)
		}
		engine.links = append(engine.links, l)
		log.Printf("[LSM] attached: lsm/%s", p.name)
	}

	return engine, nil
}

func (e *LSMEngine) Close() {
	for _, l := range e.links {
		l.Close()
	}
	e.objs.Close()
}

func (e *LSMEngine) EventReader() (*ringbuf.Reader, error) {
	return ringbuf.NewReader(e.objs.LsmEvents)
}

// loadPolicy populates BPF maps from config.
func (e *LSMEngine) loadPolicy(cfg *config.Merged) error {
	enforce := cfg.ShouldEnforce()

	flags := zionLsmPolicyFlags{
		EnforcePtrace:   boolToU32(enforce),
		EnforceSetuid:   boolToU32(enforce),
		EnforceFileOpen: boolToU32(enforce),
		EnforceMemfd:    boolToU32(enforce),
		EnforceKill:     boolToU32(enforce),
		EnforceExec:     boolToU32(enforce),
	}

	var key uint32
	if err := e.objs.LsmPolicy.Update(key, flags, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to set policy flags: %w", err)
	}

	// Allow root UID for ptrace
	var rootUID uint32
	var dummy uint8 = 1
	if err := e.objs.PtraceAllowedUids.Update(rootUID, dummy, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to add root to ptrace UIDs: %w", err)
	}

	for _, comm := range cfg.Whitelist.PtraceAllowed {
		commKey := commToKey(comm)
		if err := e.objs.PtraceAllowedComms.Update(commKey, dummy, ebpf.UpdateAny); err != nil {
			log.Printf("[LSM] WARN: ptrace comm %q: %v", comm, err)
		}
	}

	for _, comm := range cfg.Whitelist.Escalation {
		commKey := commToKey(comm)
		if err := e.objs.SetuidAllowedComms.Update(commKey, dummy, ebpf.UpdateAny); err != nil {
			log.Printf("[LSM] WARN: setuid comm %q: %v", comm, err)
		}
	}

	for _, comm := range cfg.Whitelist.CredentialReaders {
		commKey := commToKey(comm)
		if err := e.objs.CredentialReaderComms.Update(commKey, dummy, ebpf.UpdateAny); err != nil {
			log.Printf("[LSM] WARN: credential reader %q: %v", comm, err)
		}
	}

	for _, comm := range cfg.Whitelist.MemfdAllowed {
		commKey := commToKey(comm)
		if err := e.objs.MemfdAllowedComms.Update(commKey, dummy, ebpf.UpdateAny); err != nil {
			log.Printf("[LSM] WARN: memfd comm %q: %v", comm, err)
		}
	}

	for _, comm := range cfg.Prevention.BlockedBinaries {
		commKey := commToKey(comm)
		if err := e.objs.BlockedExecComms.Update(commKey, dummy, ebpf.UpdateAny); err != nil {
			log.Printf("[LSM] WARN: blocked exec %q: %v", comm, err)
		}
	}

	return nil
}

func commToKey(comm string) [16]byte {
	var key [16]byte
	copy(key[:], comm)
	return key
}

func boolToU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func HookName(hookID uint32) string {
	switch hookID {
	case 1:
		return "PTRACE_BLOCK"
	case 2:
		return "SETUID_BLOCK"
	case 3:
		return "FILE_OPEN_BLOCK"
	case 4:
		return "MEMFD_BLOCK"
	case 5:
		return "KILL_BLOCK"
	case 6:
		return "EXEC_BLOCK"
	default:
		return fmt.Sprintf("UNKNOWN_HOOK_%d", hookID)
	}
}

func MitreTechnique(hookID uint32) string {
	switch hookID {
	case 1:
		return "T1055"
	case 2:
		return "T1068"
	case 3:
		return "T1003/T1070"
	case 4:
		return "T1620"
	case 5:
		return "T1562"
	case 6:
		return "T1059"
	default:
		return "N/A"
	}
}

// StartLSMEventLogger reads block/allow decisions from the ring buffer.
// Blocks forever; run as a goroutine.
func StartLSMEventLogger(engine *LSMEngine, eventLog *logger.Logger) {
	rd, err := engine.EventReader()
	if err != nil {
		log.Fatalf("[LSM] failed to open event ring buffer: %v", err)
	}

	log.Println("[LSM] enforcement event logger active")

	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var evt LSMEvent
		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.LittleEndian, &evt,
		); err != nil {
			log.Printf("[LSM] failed to decode event: %v", err)
			continue
		}

		comm := commStr(evt.Comm[:])
		detail := commStr(evt.Detail[:])
		ts := logger.Timestamp()
		hookName := HookName(evt.Hook)
		mitre := MitreTechnique(evt.Hook)

		if evt.Decision < 0 {
			eventLog.Log(logger.Event{
				EventType: logger.EventInjection,
				Severity:  logger.SeverityCritical,
				PID:       evt.Pid,
				UID:       evt.Uid,
				Comm:      comm,
				Details: map[string]string{
					"action":  "BLOCKED_BY_LSM",
					"hook":    hookName,
					"mitre":   mitre,
					"detail":  detail,
					"verdict": "DENIED",
				},
			})

			fmt.Println()
			fmt.Println("+==========================================================+")
			fmt.Printf("|  BLOCKED: %-47s|\n",
				fmt.Sprintf("%s (%s)", hookName, mitre))
			fmt.Println("+----------------------------------------------------------+")
			fmt.Printf("|  Time:     %-46s|\n", ts)
			fmt.Printf("|  Process:  %-15s (PID: %-6d, UID: %-5d)   |\n",
				comm, evt.Pid, evt.Uid)
			if detail != "" {
				fmt.Printf("|  Detail:   %-46s|\n", truncStr(detail, 46))
			}
			fmt.Println("|  Result:   OPERATION DENIED (EPERM)                      |")
			fmt.Println("+==========================================================+")
		}
	}
}

func commStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func truncStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
