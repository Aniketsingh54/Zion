<div align="center">

# ZION

### Kernel-Level Threat Prevention & Detection Engine

*eBPF-powered security that blocks attacks in-kernel before execution. Zero race conditions.*

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-orange)](https://ebpf.io)
[![BPF-LSM](https://img.shields.io/badge/BPF--LSM-Enforce-red)](https://docs.kernel.org/bpf/prog_lsm.html)
[![Linux](https://img.shields.io/badge/Linux-6.x-FCC624?logo=linux&logoColor=black)](https://kernel.org)
[![License](https://img.shields.io/badge/License-GPL--2.0-blue)](LICENSE)

</div>

---

## What is Zion?

Zion is a **host-based intrusion prevention system** (HIPS) built on eBPF with a dual-layer architecture:

1. **BPF-LSM Prevention** -- hooks into the Linux Security Module framework to block malicious syscalls before they execute.

2. **Tracepoint Detection** -- observes kernel events for telemetry, logging, and forensics.

Traditional detect-and-respond tools race against attackers: the syscall executes, then userspace detects it and sends a kill signal. Zion's LSM hooks sit inside the syscall path -- the operation cannot proceed until Zion returns a verdict.

### Capabilities

| Capability | Mechanism | MITRE ATT&CK | Enforcement |
|---|---|---|---|
| **Process Injection** | `lsm/ptrace_access_check` | T1055 | Blocked |
| **Privilege Escalation** | `lsm/task_fix_setuid` | T1068 | Blocked |
| **Credential Access** | `lsm/file_open` | T1003.008 | Blocked |
| **Defense Evasion** | `lsm/file_open` (write) | T1070.002 | Blocked |
| **Persistence** | `lsm/file_open` (cron) | T1053.003 | Blocked |
| **Fileless Execution** | Tracepoint `sys_memfd_create` | T1620 | Detected |
| **Sensor Tampering** | `lsm/task_kill` | T1562 | Blocked |
| **Malicious Execution** | `lsm/bprm_check_security` | T1059 | Blocked |
| **Process Telemetry** | Tracepoint `sched_process_exec` | T1059 | Logged |

---

## Architecture

```
+-------------------------------------------------------------------+
|                          USERSPACE                                 |
|                                                                    |
|  +----------+    +--------------+    +-----------------------+    |
|  | main.go  |--->|  Telemetry   |    |      Detection        |    |
|  | (Loader) |    | exec_logger  |    |  injection.go          |    |
|  +----------+    +--------------+    |  privilege.go          |    |
|       |                              |  file_monitor.go       |    |
|       |          +--------------+    +----------+------------+    |
|       +--------->|  LSM Engine  |               |                 |
|       |          |  lsm/engine  |    +----------v------------+    |
|       |          |  (policy     |    |   Response Engine      |    |
|       |          |   loader)    |    |   dispatcher.go ---------> enforcer.py
|       |          +--------------+    +-----------------------+    |
|       |                                                           |
+-------+----------------- eBPF BOUNDARY --------------------------+
|       v                KERNEL SPACE                                |
|                                                                    |
|  +-------------------------------------------------------------+ |
|  |  BPF-LSM PREVENTION (Deterministic Blocking)                 | |
|  |                                                               | |
|  |  LSM: lsm/ptrace_access_check  -> BLOCK injection    -EPERM | |
|  |  LSM: lsm/task_fix_setuid      -> BLOCK priv esc     -EPERM | |
|  |  LSM: lsm/file_open            -> BLOCK cred access  -EPERM | |
|  |  LSM: lsm/task_kill            -> BLOCK sensor kill   -EPERM | |
|  |  LSM: lsm/bprm_check_security  -> BLOCK banned exec  -EPERM | |
|  |                                              +---------------| |
|  |  Policy Maps <-- config.yaml                 |  Ring Buffer  | |
|  |  (allowed UIDs, comms, blocked bins)          |  (decisions)  | |
|  +----------------------------------------------+---------------+ |
|                                                                    |
|  +-------------------------------------------------------------+ |
|  |  TRACEPOINT OBSERVATION (Telemetry & Logging)                | |
|  |                                                               | |
|  |  TP: raw_syscalls/sys_enter      -> syscall counter          | |
|  |  TP: sched/sched_process_exec    -> exec events --> RingBuf  | |
|  |  TP: syscalls/sys_enter_ptrace   -> ptrace events -> RingBuf | |
|  |  TP: syscalls/sys_enter_setuid   -> priv events --> RingBuf  | |
|  |  TP: syscalls/sys_enter_openat   -> file events --> RingBuf  | |
|  |  TP: syscalls/sys_enter_memfd    -> memfd events -> RingBuf  | |
|  |  TP: syscalls/sys_enter_kill     -> kill events --> RingBuf  | |
|  +-------------------------------------------------------------+ |
+-------------------------------------------------------------------+
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
| Linux | 6.x+ with BTF + BPF LSM | `cat /sys/kernel/security/lsm` must include `bpf` |

### Build & Run

```bash
git clone https://github.com/aniket/zion.git
cd zion

# Generate kernel headers
mkdir -p headers
bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

# Build (compiles tracepoints + LSM hooks)
make build

# Run in enforce mode (deterministic blocking)
sudo ./zion --enforce

# Or via Makefile
make enforce
```

### Operational Modes

| Mode | Command | Behavior |
|------|---------|----------|
| **ENFORCE** | `sudo ./zion --enforce` | BPF-LSM blocks attacks in-kernel |
| **ARMED** | `sudo ./zion` | Detect then SIGKILL |
| **DRY-RUN** | `sudo ./zion --no-kill` | Detection only |

---

## Demo

### Enforce Mode Startup
```
+==============================================================+
|              ZION Kernel Probe Active                         |
|          Behavioral Detection & Response Engine               |
+--------------------------------------------------------------+
|  Probes:  7 active tracepoints                               |
|  Detect:  6 attack vectors (MITRE ATT&CK mapped)            |
+==============================================================+
  Mode: ENFORCE (BPF-LSM deterministic blocking active)

[LSM] attached: lsm/ptrace_access_check
[LSM] attached: lsm/task_fix_setuid
[LSM] attached: lsm/file_open
[LSM] attached: lsm/task_kill
[LSM] attached: lsm/bprm_check_security
[ZION] BPF-LSM enforcement active -- attacks blocked in-kernel
```

### Process Injection -- BLOCKED
```
+==========================================================+
|  CRITICAL: PROCESS INJECTION DETECTED                    |
+----------------------------------------------------------+
|  Attacker: strace          (PID: 269920, UID: 1000 )    |
|  Target:   PID 269918                                    |
|  Action:   PTRACE_SEIZE                                  |
|  Status:   BLOCKED BY LSM (syscall denied in-kernel)     |
+==========================================================+
[ZION] LSM blocked ptrace for PID 269920 (strace) -- no kill needed
```

### Privilege Escalation -- BLOCKED
```
+==========================================================+
|  CRITICAL: PRIVILEGE ESCALATION DETECTED (T1068)         |
+----------------------------------------------------------+
|  Binary:   zion_exploit    (PID: 270004)                 |
|  UID:      1000 -> 0 (ROOT)                              |
|  Status:   BLOCKED BY LSM (setuid denied in-kernel)      |
+==========================================================+
[ZION] LSM blocked setuid for PID 270004 -- no kill needed
```

### Credential Access -- BLOCKED
```
+==========================================================+
|  CRITICAL: CREDENTIAL ACCESS DETECTED (T1003.008)        |
+----------------------------------------------------------+
|  Process:  cat             (PID: 270156, UID: 1000 )    |
|  File:     /etc/shadow                                   |
|  Access:   READ                                          |
+==========================================================+
[ZION] LSM blocked file access for PID 270156 (cat) -- no kill needed
```

### Sensor Tampering -- BLOCKED
```
+==========================================================+
|  CRITICAL: SENSOR TAMPERING DETECTED (T1562)             |
+----------------------------------------------------------+
|  Attacker: bash            (PID: 270471, UID: 1000 )    |
|  Signal:   SIGTERM         -> Zion (PID: 269035)         |
|  Status:   ATTEMPT TO DISABLE SECURITY SENSOR            |
+==========================================================+
[ZION] LSM blocked kill signal -- Zion protected
```

---

## Project Structure

```
zion/
├── main.go                  # Entry point, eBPF loader, CLI flags, LSM init
├── ebpf/
│   ├── zion_loader.c        # 7 tracepoint probes (observation layer)
│   └── zion_lsm.c           # 5 BPF-LSM hooks (prevention layer)
├── lsm/
│   └── engine.go            # LSM engine: load, attach, policy, event reader
├── headers/
│   ├── vmlinux.h            # Kernel BTF types (generated)
│   └── bpf/
│       ├── bpf_helpers.h    # BPF helper declarations
│       └── bpf_tracing.h    # LSM program macros (BPF_PROG)
├── config/
│   └── config.go            # YAML config loader + prevention policy
├── logger/
│   └── logger.go            # JSONL event logger + session stats
├── telemetry/
│   └── exec_logger.go       # Process execution consumer
├── detection/
│   ├── injection.go         # Ptrace injection detector (T1055)
│   ├── privilege.go         # Privilege escalation detector (T1068)
│   ├── file_monitor.go      # Credential/log/persistence monitor (T1003/T1070/T1053)
│   ├── fileless.go          # Fileless execution detector (T1620)
│   └── self_defense.go      # Sensor tampering detection (T1562)
├── response/
│   ├── dispatcher.go        # Go kill order dispatch (ARMED fallback)
│   └── enforcer.py          # Python kill daemon + pcap capture
├── attacks/
│   ├── run_all.sh           # Master runner (all attacks in sequence)
│   ├── 01_injection.sh      # T1055: strace ptrace attach
│   ├── 02_privesc.sh        # T1068: setuid(0) exploit
│   ├── 03_credential_access.sh  # T1003: /etc/shadow read
│   ├── 04_defense_evasion.sh    # T1070: history/log wiping
│   ├── 05_persistence.sh    # T1053: crontab backdoor
│   ├── 06_fileless.sh       # T1620: memfd_create payload
│   └── 07_sensor_tamper.sh  # T1562: kill Zion attempt
├── config.yaml              # Whitelists + prevention policy
├── Makefile                 # build | run | enforce | dry-run
└── docs/
    └── ARCHITECTURE.md
```

---

## Configuration

Edit `config.yaml` to control enforcement policy and whitelists:

```yaml
prevention:
  enforce: false              # Set true or use --enforce flag
  blocked_binaries: []        # e.g. ["ncat", "socat"]

whitelist:
  ptrace_allowed:             # Processes allowed to read /proc
    - ps
    - top
    - htop
    - cat
    - code
  escalation:                 # Processes allowed to setuid(0)
    - sudo
    - su
    - pkexec
  credential_readers:         # Processes allowed to read /etc/shadow
    - sshd
    - login
```

---

## Tech Stack

- **eBPF + BPF-LSM** -- Kernel-level prevention via [cilium/ebpf](https://github.com/cilium/ebpf) (CO-RE)
- **Go** -- Userspace loader, event processing, policy management
- **Python** -- Response daemon (SIGKILL + pcap)
- **bpf2go** -- eBPF C to Go bindings

---

## Why BPF-LSM?

Traditional eBPF security tools observe syscalls via tracepoints, then react:

```
Attacker -> syscall -> [tracepoint observes] -> userspace detects -> SIGKILL
                        ^ syscall already executed ^
                        Race condition: damage done
```

Zion's LSM hooks sit inside the syscall path:

```
Attacker -> syscall -> [LSM hook: verdict?] -> return -EPERM
                        ^ syscall blocked here ^
                        Deterministic: nothing executes
```

---

## License

GPL-2.0 -- required for eBPF programs that use GPL-only kernel helpers.
