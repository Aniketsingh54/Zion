<div align="center">

# ⚡ ZION

### Kernel-Level Threat Detection & Automated Response

*An eBPF-powered security monitor that sees every process, catches every injection, and kills every threat — in real time.*

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-orange)](https://ebpf.io)
[![Linux](https://img.shields.io/badge/Linux-6.x-FCC624?logo=linux&logoColor=black)](https://kernel.org)
[![License](https://img.shields.io/badge/License-GPL--2.0-blue)](LICENSE)

</div>

---

## What is Zion?

Zion is a **host-based intrusion detection and response system** (HIDS) that operates at the kernel level using eBPF. Unlike userspace security tools that can be evaded, Zion hooks directly into the Linux kernel's syscall interface — making it invisible and untamperable to attackers.

### Key Capabilities

| Capability | Technique | MITRE ATT&CK |
|---|---|---|
| **Process Telemetry** | Tracepoint on `sched_process_exec` | T1059 |
| **Injection Detection** | Tracepoint on `sys_ptrace` | T1055 |
| **Privilege Escalation** | Tracepoint on `sys_setuid` | T1068 |
| **Credential Access** | Tracepoint on `sys_openat` | T1003.008 |
| **Defense Evasion** | Log/history tampering detection | T1070.002 |
| **Persistence** | Crontab/bashrc modification | T1053.003 |
| **Fileless Execution** | Tracepoint on `sys_memfd_create` | T1620 |
| **Sensor Tampering** | Tracepoint on `sys_kill` (self-protection) | T1562 |
| **Automated Kill** | SIGKILL via Unix socket pipeline | Response |
| **Packet Capture** | tcpdump on threat detection | Forensics |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        USERSPACE                             │
│                                                              │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ main.go  │───▶│  Telemetry   │    │    Detection      │   │
│  │ (Loader) │    │ exec_logger  │    │ injection.go      │   │
│  └──────────┘    └──────────────┘    │ privilege.go      │   │
│       │                              └────────┬─────────┘   │
│       │                                       │              │
│       │                              ┌────────▼─────────┐   │
│       │                              │  Response Engine  │   │
│       │                              │  dispatcher.go ──────▶ enforcer.py
│       │                              └──────────────────┘   │
├───────┼──────────────────── eBPF BOUNDARY ──────────────────┤
│       ▼              KERNEL SPACE                            │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              zion_loader.c (eBPF Bytecode)           │    │
│  │                                                      │    │
│  │  TP: raw_syscalls/sys_enter     → syscall counter    │    │
│  │  TP: sched/sched_process_exec   → exec events ──────────▶ RingBuffer
│  │  TP: syscalls/sys_enter_ptrace  → ptrace events ────────▶ RingBuffer
│  │  TP: syscalls/sys_enter_setuid  → priv events ──────────▶ RingBuffer
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

For detailed architecture, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Quick Start

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Go | 1.21+ | [golang.org](https://golang.org/dl/) |
| Clang | 14+ | `apt install clang` |
| LLVM | 14+ | `apt install llvm` |
| bpftool | any | `apt install bpftool` |
| Linux | 5.8+ with BTF | `ls /sys/kernel/btf/vmlinux` |

### Build & Run

```bash
# Clone
git clone https://github.com/aniket/zion.git
cd zion

# Generate kernel headers
mkdir -p headers
bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

# Build (compiles eBPF C → Go bindings → binary)
make build

# Run (requires root for eBPF)
sudo ./zion
```

### Optional: Start the Python Enforcer

For automated process killing + packet capture:

```bash
# Terminal 2
sudo python3 response/enforcer.py
```

---

## Demo

### Process Telemetry
```
╔══════════════════════════════════════╗
║     ZION Kernel Probe Active         ║
╚══════════════════════════════════════╝

[ZION] Process Started: ls (PID: 5678, PPID: 1234, UID: 1000)
[ZION] Process Started: python3 (PID: 5679, PPID: 1234, UID: 1000)
```

### Injection Detection + Auto-Kill
```
╔═══════════════════════════════════════════════════════════╗
║  ⚠️  CRITICAL: PROCESS INJECTION DETECTED                ║
╠═══════════════════════════════════════════════════════════╣
║  Attacker: strace          (PID: 9876, UID: 1000 )      ║
║  Target:   PID 9875                                      ║
║  Action:   PTRACE_SEIZE                                  ║
╚═══════════════════════════════════════════════════════════╝
[ZION] 🗡️  Kill order dispatched → PID 9876 (strace)
```

### Privilege Escalation Monitoring
```
[ZION] INFO: Expected privilege transition: sudo (PID: 4321) UID 1000 → 0

╔═══════════════════════════════════════════════════════════╗
║  🔴 CRITICAL: PRIVILEGE ESCALATION DETECTED (T1068)      ║
║  Binary:   exploit         (PID: 6666)                   ║
║  UID:      1000 → 0 (ROOT)                               ║
║  Status:   UNAUTHORIZED ELEVATION                        ║
╚═══════════════════════════════════════════════════════════╝
[ZION] 🗡️  Kill order dispatched → PID 6666 (exploit)
```

---

## Project Structure

```
zion/
├── main.go                  # Entry point, eBPF loader, CLI flags
├── ebpf/
│   └── zion_loader.c        # 9 eBPF probes (C, compiled via bpf2go)
├── headers/
│   ├── vmlinux.h            # Kernel BTF types (generated)
│   └── bpf/bpf_helpers.h    # Vendored BPF helper declarations
├── config/
│   └── config.go            # YAML config loader + whitelist helpers
├── logger/
│   └── logger.go            # JSONL event logger + session stats
├── telemetry/
│   └── exec_logger.go       # Process execution consumer + reverse shell patterns
├── detection/
│   ├── injection.go         # Ptrace injection detector (T1055)
│   ├── privilege.go         # Privilege escalation detector (T1068)
│   ├── file_monitor.go      # Credential/log/persistence monitor (T1003/T1070/T1053)
│   ├── fileless.go          # Fileless execution detector (T1620)
│   └── self_defense.go      # Sensor tampering + dup2 detection (T1562)
├── response/
│   ├── dispatcher.go        # Go → Python kill order dispatch
│   └── enforcer.py          # Python kill daemon + pcap capture
├── attacks/                 # Attack simulation scripts for demos
│   ├── run_all.sh           # Master runner (all 8 attacks in sequence)
│   ├── 01_injection.sh      # T1055: strace ptrace attach
│   ├── 02_privesc.sh        # T1068: setuid(0) exploit
│   ├── 04_credential_access.sh  # T1003: /etc/shadow read
│   ├── 05_defense_evasion.sh    # T1070: history/log wiping
│   ├── 06_persistence.sh    # T1053: crontab backdoor
│   ├── 07_fileless.sh       # T1620: memfd_create payload
│   └── 08_sensor_tamper.sh  # T1562: kill Zion attempt
├── scripts/
│   └── kill_switch.sh       # Manual threat termination tool
├── config.yaml              # Process whitelist + response configuration
├── Makefile                 # Build automation
└── docs/
    └── ARCHITECTURE.md      # Detailed system design
```

---

## Configuration

Edit `config.yaml` to whitelist noisy or expected processes:

```yaml
whitelist:
  exec:
    - git
    - code
    - node
  escalation:
    - sudo
    - su
    - pkexec
```

---

## Tech Stack

- **eBPF** — Kernel-level instrumentation via [cilium/ebpf](https://github.com/cilium/ebpf) (CO-RE)
- **Go** — Userspace loader, event processing, detection engine
- **Python** — Automated response daemon (SIGKILL + pcap)
- **bpf2go** — Compile-once eBPF C → Go bindings

---

## License

GPL-2.0 — required for eBPF programs that use GPL-only kernel helpers.
