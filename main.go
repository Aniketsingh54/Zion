package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/aniket/zion/detection"
	"github.com/aniket/zion/telemetry"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip zion ebpf/zion_loader.c -- -Iheaders -O2 -g -target bpf

func main() {
	// ── Gate: must be root ──────────────────────────────────────────────
	if os.Getuid() != 0 {
		log.Fatal("[ZION] Root privileges required. Run with: sudo ./zion")
	}

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

	// ── PR #1: Attach tracepoint — raw_syscalls/sys_enter ───────────────
	tp1, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.ZionProbe, nil)
	if err != nil {
		log.Fatalf("[ZION] Failed to attach syscall tracepoint: %v", err)
	}
	defer tp1.Close()

	// ── PR #2: Attach tracepoint — sched/sched_process_exec ─────────────
	tp2, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExec, nil)
	if err != nil {
		log.Fatalf("[ZION] Failed to attach exec tracepoint: %v", err)
	}
	defer tp2.Close()

	// ── PR #3: Attach tracepoint — syscalls/sys_enter_ptrace ────────────
	tp3, err := link.Tracepoint("syscalls", "sys_enter_ptrace", objs.TracePtrace, nil)
	if err != nil {
		log.Fatalf("[ZION] Failed to attach ptrace tracepoint: %v", err)
	}
	defer tp3.Close()

	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║     ZION Kernel Probe Active         ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Println("Monitoring process executions... Press Ctrl+C to exit.")

	// ── Start telemetry & detection goroutines ──────────────────────────
	go telemetry.StartExecLogger(objs.ExecEvents)
	go detection.StartInjectionDetector(objs.PtraceEvents)

	// ── Background: read the syscall counter every 5s ───────────────────
	go func() {
		var key uint32
		for {
			time.Sleep(5 * time.Second)
			var count uint64
			if err := objs.ZionStatus.Lookup(key, &count); err != nil {
				log.Printf("[ZION] Map read error: %v", err)
			} else {
				fmt.Printf("\r[ZION] Syscalls observed: %-20d", count)
			}
		}
	}()

	// ── Wait for interrupt ──────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n[ZION] Shutting down. Kernel probes removed.")
}
