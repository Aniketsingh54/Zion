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

	// ── Attach tracepoint: raw_syscalls/sys_enter ───────────────────────
	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.ZionProbe, nil)
	if err != nil {
		log.Fatalf("[ZION] Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║     ZION Kernel Probe Active         ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Println("Press Ctrl+C to detach and exit.")

	// ── Background: read the syscall counter every 2s ───────────────────
	go func() {
		var key uint32
		for {
			time.Sleep(2 * time.Second)
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
