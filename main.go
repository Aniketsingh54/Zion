package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/aniket/zion/config"
	"github.com/aniket/zion/detection"
	"github.com/aniket/zion/logger"
	"github.com/aniket/zion/lsm"
	"github.com/aniket/zion/telemetry"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip zion ebpf/zion_loader.c -- -Iheaders -O2 -g -target bpf

func main() {
	// ── CLI flags ────────────────────────────────────────────────────────
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	logDir := flag.String("log-dir", "", "Directory for JSON event logs (overrides config)")
	noKill := flag.Bool("no-kill", false, "Dry-run mode: detect threats but don't kill processes")
	verbose := flag.Bool("verbose", false, "Show all exec events including whitelisted")
	stats := flag.Bool("stats", true, "Print event statistics on shutdown")
	enforce := flag.Bool("enforce", false, "Enable BPF-LSM enforcement (deterministic blocking)")
	flag.Parse()

	// ── Gate: must be root ──────────────────────────────────────────────
	if os.Getuid() != 0 {
		log.Fatal("[ZION] Root privileges required. Run with: sudo ./zion")
	}

	// ── Load configuration ──────────────────────────────────────────────
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[ZION] Failed to load config: %v", err)
	}

	merged := config.Merge(cfg, config.RuntimeOverrides{
		NoKill:  *noKill,
		Verbose: *verbose,
		LogDir:  *logDir,
		Stats:   *stats,
		Enforce: *enforce,
	})

	// ── Initialize event logger ─────────────────────────────────────────
	eventLog, err := logger.New(merged.Logging.Directory, merged.Logging.Enabled)
	if err != nil {
		log.Fatalf("[ZION] Failed to initialize logger: %v", err)
	}
	defer eventLog.Close()

	// ── Lift the eBPF memory lock ───────────────────────────────────────
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("[ZION] Failed to remove memlock: %v", err)
	}

	// ── Load compiled eBPF objects into the kernel ──────────────────────
	var objs zionObjects
	if err := loadZionObjects(&objs, nil); err != nil {
		log.Fatalf("[ZION] Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// ── Write Zion's PID into the eBPF map (for self-defense) ───────────
	var pidKey uint32
	zionPID := uint32(os.Getpid())
	if err := objs.ZionPid.Update(pidKey, zionPID, 0); err != nil {
		log.Printf("[ZION] WARN: Failed to set self-defense PID: %v", err)
	}

	// ── Attach tracepoint — raw_syscalls/sys_enter ──────────────────────
	tp1, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.ZionProbe, nil)
	if err != nil {
		log.Fatalf("[ZION] Failed to attach syscall tracepoint: %v", err)
	}
	defer tp1.Close()

	// ── Attach tracepoint — sched/sched_process_exec ────────────────────
	tp2, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExec, nil)
	if err != nil {
		log.Fatalf("[ZION] Failed to attach exec tracepoint: %v", err)
	}
	defer tp2.Close()

	// ── Attach tracepoint — syscalls/sys_enter_ptrace ───────────────────
	tp3, err := link.Tracepoint("syscalls", "sys_enter_ptrace", objs.TracePtrace, nil)
	if err != nil {
		log.Fatalf("[ZION] Failed to attach ptrace tracepoint: %v", err)
	}
	defer tp3.Close()

	// ── Attach tracepoint — syscalls/sys_enter_setuid ───────────────────
	tp4, err := link.Tracepoint("syscalls", "sys_enter_setuid", objs.TraceSetuid, nil)
	if err != nil {
		log.Fatalf("[ZION] Failed to attach setuid tracepoint: %v", err)
	}
	defer tp4.Close()

	// ── Attach tracepoint — syscalls/sys_enter_openat ───────────────────
	tp5, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("[ZION] Failed to attach openat tracepoint: %v", err)
	}
	defer tp5.Close()

	// 6. Connect (Removed)
	// tp6, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	// if err != nil { ... }
	// defer tp6.Close()

	// ── Attach tracepoint — syscalls/sys_enter_memfd_create ─────────────
	tp7, err := link.Tracepoint("syscalls", "sys_enter_memfd_create", objs.TraceMemfdCreate, nil)
	if err != nil {
		log.Fatalf("[ZION] Failed to attach memfd_create tracepoint: %v", err)
	}
	defer tp7.Close()

	// 8. Dup2 (Removed)
	// tp8, err := link.Tracepoint("syscalls", "sys_enter_dup2", objs.TraceDup2, nil)
	// if err != nil { ... }
	// defer tp8.Close()

	// ── Attach tracepoint — syscalls/sys_enter_kill ─────────────────────
	tp9, err := link.Tracepoint("syscalls", "sys_enter_kill", objs.TraceKill, nil)
	if err != nil {
		log.Fatalf("[ZION] Failed to attach kill tracepoint: %v", err)
	}
	defer tp9.Close()

	// ── Banner ──────────────────────────────────────────────────────────
	fmt.Println("+==============================================================+")
	fmt.Println("|              ZION Kernel Probe Active                         |")
	fmt.Println("|          Behavioral Detection & Response Engine               |")
	fmt.Println("+--------------------------------------------------------------+")
	fmt.Println("|  Probes:  7 active tracepoints                               |")
	fmt.Println("|  Detect:  6 attack vectors (MITRE ATT&CK mapped)             |")
	fmt.Println("+==============================================================+")
	if merged.ShouldEnforce() {
		fmt.Println("  Mode: ENFORCE (BPF-LSM deterministic blocking active)")
	} else if merged.NoKill {
		fmt.Println("  Mode: DRY-RUN (detection only, no auto-kill)")
	} else {
		fmt.Println("  Mode: ARMED (auto-kill enabled, detect-then-respond)")
	}
	fmt.Printf("  Config: %s\n", *configPath)
	fmt.Printf("  Self-defense PID: %d\n", zionPID)
	fmt.Println()
	fmt.Println("  Detection Coverage:")
	fmt.Println("  ├── T1055  Process Injection (ptrace)")
	fmt.Println("  ├── T1068  Privilege Escalation (setuid)")
	// fmt.Println("  ├── T1059  Reverse Shell (connect + dup2) [DISABLED]")
	fmt.Println("  ├── T1003  Credential Access (file reads)")
	fmt.Println("  ├── T1070  Defense Evasion (log tampering)")
	fmt.Println("  ├── T1053  Persistence (crontab/bashrc)")
	fmt.Println("  ├── T1620  Fileless Execution (memfd_create)")
	fmt.Println("  └── T1562  Sensor Tampering (kill protection)")
	fmt.Println()
	fmt.Println("Monitoring... Press Ctrl+C to exit.")
	fmt.Println()

	// ── Start BPF-LSM enforcement engine (if enabled) ───────────────
	var lsmEngine *lsm.LSMEngine
	if merged.ShouldEnforce() {
		var err error
		lsmEngine, err = lsm.New(merged, eventLog)
		if err != nil {
			log.Printf("[ZION] WARN: LSM enforcement unavailable: %v", err)
			log.Println("[ZION] Falling back to detect-and-respond mode.")
		} else {
			defer lsmEngine.Close()
			go lsm.StartLSMEventLogger(lsmEngine, eventLog)
			fmt.Println("[ZION] BPF-LSM enforcement active -- attacks blocked in-kernel")
		}
	}

	// ── Start telemetry & detection goroutines ──────────────────────────
	go telemetry.StartExecLogger(objs.ExecEvents, merged, eventLog)
	go detection.StartInjectionDetector(objs.PtraceEvents, merged, eventLog)
	go detection.StartPrivilegeDetector(objs.PrivEvents, merged, eventLog)
	go detection.StartFileMonitor(objs.FileEvents, merged, eventLog)
	// go detection.StartReverseShellDetector(objs.ConnectEvents, merged, eventLog)
	go detection.StartFilelessDetector(objs.MemfdEvents, merged, eventLog)
	// go detection.StartDup2Detector(objs.Dup2Events, merged, eventLog)
	go detection.StartSelfDefenseDetector(objs.KillEvents, merged, eventLog)

	// ── Background: read the syscall counter every 5s ───────────────────
	go func() {
		var key uint32
		for {
			time.Sleep(5 * time.Second)
			var count uint64
			if err := objs.ZionStatus.Lookup(key, &count); err != nil {
				log.Printf("[ZION] Map read error: %v", err)
			} else {
				fmt.Printf("\r[ZION] [%s] Syscalls observed: %-20d",
					logger.Timestamp(), count)
			}
		}
	}()

	// ── Wait for interrupt ──────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Printf("\n[ZION] [%s] Shutting down. Kernel probes removed.\n", logger.Timestamp())

	// ── Print session stats ─────────────────────────────────────────────
	if merged.Stats {
		eventLog.PrintStats()
	}
}
