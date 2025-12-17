# Zion — System Architecture

## Overview

Zion is a kernel-to-userspace security pipeline built on eBPF. It operates across two privilege domains: **kernel space** (where probes execute on every relevant syscall) and **userspace** (where Go processes events, applies policy, and dispatches responses).

## Data Flow

```
  Syscall Event
       │
       ▼
┌──────────────┐
│  eBPF Probe  │  Runs inside the kernel, zero-copy
│  (C code)    │  Filters in-kernel to reduce noise
└──────┬───────┘
       │ RingBuffer (lock-free, per-event)
       ▼
┌──────────────┐
│  Go Consumer │  Decodes binary events
│  (ringbuf)   │  Applies detection policy
└──────┬───────┘
       │ Kill Order (JSON over Unix socket)
       ▼
┌──────────────┐
│  Enforcer    │  Python daemon
│  (response)  │  SIGKILL + tcpdump capture
└──────────────┘
```

## eBPF Probes

All probes live in `ebpf/zion_loader.c` and are compiled to eBPF bytecode via `bpf2go`.

| Probe | Hook Point | Purpose | Map Type |
|-------|-----------|---------|----------|
| `zion_probe` | `raw_syscalls/sys_enter` | Syscall counter (liveness) | Array |
| `trace_exec` | `sched/sched_process_exec` | Process execution telemetry | RingBuffer |
| `trace_ptrace` | `syscalls/sys_enter_ptrace` | Injection detection | RingBuffer |
| `trace_setuid` | `syscalls/sys_enter_setuid` | Privilege escalation | RingBuffer |

### Why Tracepoints over Kprobes?

- **Stable ABI**: Tracepoints are kernel-maintained interfaces; kprobes attach to internal functions that can change between versions.
- **Typed arguments**: Tracepoints provide structured access to syscall arguments without register parsing.
- **Lower overhead**: No function prologue interception.

## Detection Policies

### Injection Detection (T1055)
```
IF ptrace_request IN (ATTACH, SEIZE)
  AND attacker_uid != 0 (not root)
  AND attacker_pid != parent_of(target_pid)
THEN → CRITICAL ALERT + AUTO-KILL
```

### Privilege Escalation (T1068)
```
IF setuid(new_uid=0)
  AND old_uid != 0 (was non-root)
  AND comm NOT IN allowlist (sudo, su, pkexec, ...)
THEN → CRITICAL ALERT + AUTO-KILL
```

## Response Pipeline

```
Detection Alert
     │
     ├── Log to stdout (always)
     │
     └── dispatch.KillOrder{} (async goroutine)
              │
              ├── Unix socket → enforcer.py
              │       ├── os.kill(SIGKILL)
              │       └── tcpdump → .pcap
              │
              └── Fallback: direct os.Kill() from Go
```

The response system is **fail-safe**: if the Python enforcer is not running, Go kills the process directly. The enforcer adds forensic packet capture.

## CO-RE (Compile Once — Run Everywhere)

Zion uses `vmlinux.h` generated from the host's BTF (BPF Type Format) data. This means:
- The eBPF code is compiled once and runs on any kernel with BTF support (5.8+).
- No kernel headers needed at runtime.
- Portable across distributions.

## Performance

- eBPF probes execute in **nanoseconds** per event, in kernel context.
- RingBuffer is **lock-free** and **zero-copy** for event delivery.
- Go consumers process events asynchronously — no blocking in the kernel.
- Typical overhead: **< 1% CPU** with all probes active.
