//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// ═══════════════════════════════════════════════════════════════════════
// PR #1 — Syscall counter (proves probe is alive)
// ═══════════════════════════════════════════════════════════════════════

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} zion_status SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int zion_probe(void *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&zion_status, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// PR #2 — Process Execution Telemetry (sched_process_exec)
// ═══════════════════════════════════════════════════════════════════════

#define TASK_COMM_LEN 64

// Event struct shared with Go userspace.
struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8  comm[TASK_COMM_LEN];
};

// Ring buffer for streaming exec events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} exec_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(void *ctx) {
    struct exec_event *evt;

    // Reserve space in the ring buffer
    evt = bpf_ringbuf_reserve(&exec_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    // PID (lower 32 bits of pid_tgid)
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)(pid_tgid >> 32);

    // UID (lower 32 bits of uid_gid)
    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = (__u32)uid_gid;

    // Command name
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // PPID — read from current task's real_parent
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&evt->ppid, sizeof(evt->ppid), &parent->tgid);

    // Submit the event
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// PR #3 — Anti-Evasion & Injection Detection (sys_ptrace)
// ═══════════════════════════════════════════════════════════════════════

#define PTRACE_ATTACH 16
#define PTRACE_SEIZE  0x4206

// Context struct for tracepoint/syscalls/sys_enter_ptrace
struct sys_enter_ptrace_args {
    __u64 pad;              // common trace event header
    __s32 __syscall_nr;
    __u32 pad2;
    __s64 request;          // PTRACE_ATTACH, PTRACE_SEIZE, etc.
    __s64 pid;              // target PID
};

// Event struct sent to Go userspace.
struct ptrace_event {
    __u32 attacker_pid;
    __u32 target_pid;
    __u32 attacker_uid;
    __u32 request;
    __u8  attacker_comm[TASK_COMM_LEN];
};

// Ring buffer for ptrace alerts.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} ptrace_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct sys_enter_ptrace_args *ctx) {
    // Only care about PTRACE_ATTACH and PTRACE_SEIZE
    __s64 req = ctx->request;
    if (req != PTRACE_ATTACH && req != PTRACE_SEIZE) {
        return 0;
    }

    struct ptrace_event *evt = bpf_ringbuf_reserve(&ptrace_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->attacker_pid = (__u32)(pid_tgid >> 32);
    evt->target_pid   = (__u32)ctx->pid;
    evt->request      = (__u32)req;

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->attacker_uid = (__u32)uid_gid;

    bpf_get_current_comm(&evt->attacker_comm, sizeof(evt->attacker_comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// PR #4 — Privilege Escalation Hunter (setuid monitoring)
// ═══════════════════════════════════════════════════════════════════════

// Context struct for tracepoint/syscalls/sys_enter_setuid
struct sys_enter_setuid_args {
    __u64 pad;          // common trace header
    __s32 __syscall_nr;
    __u32 pad2;
    __u64 uid;          // desired new UID
};

// Event struct for privilege transitions.
struct priv_event {
    __u32 pid;
    __u32 old_uid;
    __u32 new_uid;
    __u32 pad;
    __u8  comm[TASK_COMM_LEN];
};

// Ring buffer for privilege escalation events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} priv_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct sys_enter_setuid_args *ctx) {
    __u32 new_uid = (__u32)ctx->uid;

    // Get the current (old) UID
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 old_uid = (__u32)uid_gid;

    // Only care about transitions TO root (new_uid == 0)
    // and FROM non-root (old_uid != 0)
    if (new_uid != 0 || old_uid == 0) {
        return 0;
    }

    struct priv_event *evt = bpf_ringbuf_reserve(&priv_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid     = (__u32)(pid_tgid >> 32);
    evt->old_uid = old_uid;
    evt->new_uid = new_uid;
    evt->pad     = 0;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// PR #7 — File Access Monitoring (sys_openat)
// Detects: Credential Access (T1003), Defense Evasion (T1070),
//          Persistence (T1053)
// ═══════════════════════════════════════════════════════════════════════

#define FILENAME_LEN 128

// Context struct for tracepoint/syscalls/sys_enter_openat
struct sys_enter_openat_args {
    __u64 pad;
    __s32 __syscall_nr;
    __u32 pad2;
    __s64 dfd;
    const char *filename;
    __s64 flags;
    __s64 mode;
};

// Event sent to Go for file access analysis.
struct file_event {
    __u32 pid;
    __u32 uid;
    __u32 flags;           // O_RDONLY, O_WRONLY, O_RDWR, O_TRUNC, etc.
    __u32 pad;
    __u8  comm[TASK_COMM_LEN];
    __u8  filename[FILENAME_LEN];
};

// Ring buffer for file access events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MB
} file_events SEC(".maps");

// Simple byte comparison helper (eBPF-safe, bounded loop).
static __always_inline int match_prefix(const char *buf, const char *prefix, int len) {
    for (int i = 0; i < len; i++) {
        if (buf[i] != prefix[i])
            return 0;
        if (prefix[i] == '\0')
            return 1;
    }
    return 1;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_openat_args *ctx) {
    // Read filename from user-space pointer
    char fname[FILENAME_LEN];
    int ret = bpf_probe_read_user_str(fname, sizeof(fname), ctx->filename);
    if (ret <= 0) {
        return 0;
    }

    // ── Kernel-side filter: only emit events for sensitive paths ──
    // This prevents flooding userspace with millions of benign opens.
    int dominated = 0;

    // Credential files
    if (match_prefix(fname, "/etc/shadow", 12))    dominated = 1;
    if (match_prefix(fname, "/etc/gshadow", 13))   dominated = 1;
    if (match_prefix(fname, "/etc/passwd", 12))     dominated = 1;

    // Log files (defense evasion targets)
    if (match_prefix(fname, "/var/log/", 9))        dominated = 1;

    // History files
    if (match_prefix(fname, ".bash_history", 14))   dominated = 1;

    // Persistence targets
    if (match_prefix(fname, "/etc/crontab", 13))    dominated = 1;
    if (match_prefix(fname, "/etc/cron.", 10))       dominated = 1;
    if (match_prefix(fname, "/var/spool/cron", 15))  dominated = 1;
    if (match_prefix(fname, ".bashrc", 8))           dominated = 1;
    if (match_prefix(fname, ".profile", 9))          dominated = 1;

    // proc maps (credential dumping)
    if (match_prefix(fname, "/proc/", 6))  {
        // Check for /proc/*/maps or /proc/*/mem
        for (int i = 6; i < 20 && i < ret; i++) {
            if (fname[i] == '/') {
                if (match_prefix(&fname[i], "/maps", 5))  dominated = 1;
                if (match_prefix(&fname[i], "/mem", 4))   dominated = 1;
                break;
            }
        }
    }

    if (!dominated) {
        return 0;
    }

    // ── Emit event ──
    struct file_event *evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid   = (__u32)(pid_tgid >> 32);

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid   = (__u32)uid_gid;

    evt->flags = (__u32)ctx->flags;
    evt->pad   = 0;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // Copy filename
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), ctx->filename);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// PR #7 — Outbound Connection Monitor (sys_connect)
// Detects: Reverse Shell (T1059.004), C2 Beaconing
// ═══════════════════════════════════════════════════════════════════════

// Context struct for tracepoint/syscalls/sys_enter_connect
struct sys_enter_connect_args {
    __u64 pad;
    __s32 __syscall_nr;
    __u32 pad2;
    __s64 fd;
    struct sockaddr *uservaddr;
    __s64 addrlen;
};

// Event sent to Go for connection analysis.
struct connect_event {
    __u32 pid;
    __u32 uid;
    __u16 port;            // destination port (network byte order → converted)
    __u16 family;          // AF_INET or AF_INET6
    __u32 dst_ip4;         // IPv4 destination (network byte order)
    __u8  comm[TASK_COMM_LEN];
};

// Ring buffer for connect events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} connect_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct sys_enter_connect_args *ctx) {
    // Read the sockaddr_family first
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &ctx->uservaddr->sa_family);

    // Only care about IPv4 (AF_INET = 2) for now
    if (family != 2) {
        return 0;
    }

    // Read the full sockaddr_in
    struct sockaddr_in addr = {};
    bpf_probe_read_user(&addr, sizeof(addr), ctx->uservaddr);

    // Filter out loopback (127.x.x.x) and unspecified (0.0.0.0)
    // to reduce noise — but still useful for demo
    __u32 ip = addr.sin_addr.s_addr;

    // Skip Unix domain sockets connecting to port 0
    __u16 port = __builtin_bswap16(addr.sin_port);
    if (port == 0) {
        return 0;
    }

    struct connect_event *evt = bpf_ringbuf_reserve(&connect_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid    = (__u32)(pid_tgid >> 32);

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid    = (__u32)uid_gid;

    evt->port   = port;
    evt->family = family;
    evt->dst_ip4 = ip;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// Fileless Malware Detection — memfd_create (T1620)
// Attackers use memfd_create to execute code directly from RAM
// ═══════════════════════════════════════════════════════════════════════

// Context struct for tracepoint/syscalls/sys_enter_memfd_create
struct sys_enter_memfd_create_args {
    __u64 pad;
    __s32 __syscall_nr;
    __u32 pad2;
    const char *uname;        // name for the anonymous fd
    __u64 flags;
};

// Event for memfd_create calls.
struct memfd_event {
    __u32 pid;
    __u32 uid;
    __u32 flags;
    __u32 pad;
    __u8  comm[TASK_COMM_LEN];
    __u8  name[64];           // memfd name argument
};

// Ring buffer for memfd events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} memfd_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct sys_enter_memfd_create_args *ctx) {
    struct memfd_event *evt = bpf_ringbuf_reserve(&memfd_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid   = (__u32)(pid_tgid >> 32);

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid   = (__u32)uid_gid;

    evt->flags = (__u32)ctx->flags;
    evt->pad   = 0;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_probe_read_user_str(evt->name, sizeof(evt->name), ctx->uname);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// Reverse Shell Enhancement — dup2 FD Redirection
// Detects shell processes redirecting stdin/stdout/stderr to sockets
// ═══════════════════════════════════════════════════════════════════════

// Context struct for tracepoint/syscalls/sys_enter_dup2
struct sys_enter_dup2_args {
    __u64 pad;
    __s32 __syscall_nr;
    __u32 pad2;
    __u64 oldfd;
    __u64 newfd;
};

// Event for dup2 calls.
struct dup2_event {
    __u32 pid;
    __u32 uid;
    __u32 oldfd;
    __u32 newfd;
    __u8  comm[TASK_COMM_LEN];
};

// Ring buffer for dup2 events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} dup2_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_dup2(struct sys_enter_dup2_args *ctx) {
    // Only care about redirections into stdin(0), stdout(1), stderr(2)
    __u64 newfd = ctx->newfd;
    if (newfd > 2) {
        return 0;
    }

    struct dup2_event *evt = bpf_ringbuf_reserve(&dup2_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid   = (__u32)(pid_tgid >> 32);

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid   = (__u32)uid_gid;

    evt->oldfd = (__u32)ctx->oldfd;
    evt->newfd = (__u32)newfd;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// Sensor Tampering Detection — sys_kill (T1562)
// Detects attempts to kill Zion's own process or send stop signals
// ═══════════════════════════════════════════════════════════════════════

// Context struct for tracepoint/syscalls/sys_enter_kill
struct sys_enter_kill_args {
    __u64 pad;
    __s32 __syscall_nr;
    __u32 pad2;
    __s64 target_pid;
    __s64 sig;
};

// Event for kill calls.
struct kill_event {
    __u32 caller_pid;
    __u32 caller_uid;
    __s32 target_pid;
    __s32 signal;
    __u8  comm[TASK_COMM_LEN];
};

// Ring buffer for kill events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} kill_events SEC(".maps");

// Map to store Zion's own PID (set from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} zion_pid SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_kill")
int trace_kill(struct sys_enter_kill_args *ctx) {
    __s64 sig = ctx->sig;

    // Only care about dangerous signals: SIGKILL(9), SIGSTOP(19), SIGTERM(15)
    if (sig != 9 && sig != 15 && sig != 19) {
        return 0;
    }

    // Check if the target is Zion's own PID
    __u32 key = 0;
    __u32 *zpid = bpf_map_lookup_elem(&zion_pid, &key);
    if (!zpid) {
        return 0;
    }

    __s64 target = ctx->target_pid;
    if ((__u32)target != *zpid) {
        return 0;
    }

    // Someone is trying to kill Zion!
    struct kill_event *evt = bpf_ringbuf_reserve(&kill_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->caller_pid = (__u32)(pid_tgid >> 32);

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->caller_uid = (__u32)uid_gid;

    evt->target_pid = (__s32)target;
    evt->signal     = (__s32)sig;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
