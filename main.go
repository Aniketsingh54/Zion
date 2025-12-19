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

	// ── Banner ──────────────────────────────────────────────────────────
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║     ZION Kernel Probe Active         ║")
	fmt.Println("╚══════════════════════════════════════╝")
	if merged.NoKill {
		fmt.Println("⚙️  Mode: DRY-RUN (detection only, no auto-kill)")
	} else {
		fmt.Println("⚙️  Mode: ARMED (auto-kill enabled)")
	}
	fmt.Printf("⚙️  Config: %s\n", *configPath)
	fmt.Printf("⚙️  Whitelisted commands: %d exec, %d escalation\n",
		len(merged.Whitelist.Exec), len(merged.Whitelist.Escalation))
	fmt.Println("Monitoring process executions... Press Ctrl+C to exit.")
	fmt.Println()

	// ── Start telemetry & detection goroutines ──────────────────────────
	go telemetry.StartExecLogger(objs.ExecEvents, merged, eventLog)
	go detection.StartInjectionDetector(objs.PtraceEvents, merged, eventLog)
	go detection.StartPrivilegeDetector(objs.PrivEvents, merged, eventLog)

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
