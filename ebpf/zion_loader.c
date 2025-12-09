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

char LICENSE[] SEC("license") = "GPL";
