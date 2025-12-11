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

char LICENSE[] SEC("license") = "GPL";
