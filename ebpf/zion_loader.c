//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 112;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 114;

// --- Syscall counter ---

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

// --- Process execution telemetry (sched_process_exec) ---

#define TASK_COMM_LEN 64

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} exec_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(void *ctx) {
    struct exec_event *evt;
    evt = bpf_ringbuf_reserve(&exec_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)(pid_tgid >> 32);

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = (__u32)uid_gid;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&evt->ppid, sizeof(evt->ppid), &parent->tgid);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// --- Ptrace injection detection (T1055) ---

#define PTRACE_ATTACH 16
#define PTRACE_SEIZE  0x4206

struct sys_enter_ptrace_args {
    __u64 pad;
    __s32 __syscall_nr;
    __u32 pad2;
    __s64 request;
    __s64 pid;
};

struct ptrace_event {
    __u32 attacker_pid;
    __u32 target_pid;
    __u32 attacker_uid;
    __u32 request;
    __u8  attacker_comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ptrace_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct sys_enter_ptrace_args *ctx) {
    __s64 req = ctx->request;
    if (req != PTRACE_ATTACH && req != PTRACE_SEIZE)
        return 0;

    struct ptrace_event *evt = bpf_ringbuf_reserve(&ptrace_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

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

// --- Privilege escalation detection (T1068) ---

struct sys_enter_setuid_args {
    __u64 pad;
    __s32 __syscall_nr;
    __u32 pad2;
    __u64 uid;
};

struct priv_event {
    __u32 pid;
    __u32 old_uid;
    __u32 new_uid;
    __u32 pad;
    __u8  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} priv_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct sys_enter_setuid_args *ctx) {
    __u32 new_uid = (__u32)ctx->uid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 old_uid = (__u32)uid_gid;

    // Only escalation to root from non-root
    if (new_uid != 0 || old_uid == 0)
        return 0;

    struct priv_event *evt = bpf_ringbuf_reserve(&priv_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid     = (__u32)(pid_tgid >> 32);
    evt->old_uid = old_uid;
    evt->new_uid = new_uid;
    evt->pad     = 0;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// --- File access monitoring (T1003/T1070/T1053) ---

#define FILENAME_LEN 64

struct sys_enter_openat_args {
    __u64 pad;
    __s32 __syscall_nr;
    __u32 pad2;
    __s64 dfd;
    const char *filename;
    __s64 flags;
    __s64 mode;
};

struct file_event {
    __u32 pid;
    __u32 uid;
    __u32 flags;
    __u32 pad;
    __u8  comm[TASK_COMM_LEN];
    __u8  filename[FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} file_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_openat_args *ctx) {
    char prefix[8];
    if (bpf_probe_read_user(prefix, sizeof(prefix), ctx->filename) < 0)
        return 0;

    // Fast pre-filter on path prefix
    int hit = 0;
    if (prefix[0] == '/' && prefix[1] == 'e' && prefix[2] == 't' && prefix[3] == 'c')
        hit = 1;  // /etc/*
    if (prefix[0] == '/' && prefix[1] == 'v' && prefix[2] == 'a' && prefix[3] == 'r')
        hit = 1;  // /var/*
    if (prefix[0] == '/' && prefix[1] == 'p' && prefix[2] == 'r' && prefix[3] == 'o')
        hit = 1;  // /proc/*
    if (prefix[0] == '.' && (prefix[1] == 'b' || prefix[1] == 'p' || prefix[1] == 'z'))
        hit = 1;  // .bashrc, .profile, .zshrc, .bash_history
    if (prefix[0] == '/' && prefix[1] == 'h' && prefix[2] == 'o' && prefix[3] == 'm')
        hit = 1;  // /home/*
    if (prefix[0] == '/' && prefix[1] == 'r' && prefix[2] == 'o' && prefix[3] == 'o')
        hit = 1;  // /root/*

    if (!hit)
        return 0;

    struct file_event *evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid   = (__u32)(pid_tgid >> 32);
    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid   = (__u32)uid_gid;
    evt->flags = (__u32)ctx->flags;
    evt->pad   = 0;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), ctx->filename);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// --- Fileless execution detection via memfd_create (T1620) ---

struct sys_enter_memfd_create_args {
    __u64 pad;
    __s32 __syscall_nr;
    __u32 pad2;
    const char *uname;
    __u64 flags;
};

struct memfd_event {
    __u32 pid;
    __u32 uid;
    __u32 flags;
    __u32 pad;
    __u8  comm[TASK_COMM_LEN];
    __u8  name[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} memfd_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct sys_enter_memfd_create_args *ctx) {
    struct memfd_event *evt = bpf_ringbuf_reserve(&memfd_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

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

// --- Sensor tampering detection via sys_kill (T1562) ---

struct sys_enter_kill_args {
    __u64 pad;
    __s32 __syscall_nr;
    __u32 pad2;
    __s64 target_pid;
    __s64 sig;
};

struct kill_event {
    __u32 caller_pid;
    __u32 caller_uid;
    __s32 target_pid;
    __s32 signal;
    __u8  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} kill_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} zion_pid SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_kill")
int trace_kill(struct sys_enter_kill_args *ctx) {
    __s64 sig = ctx->sig;

    if (sig != 9 && sig != 15 && sig != 19)
        return 0;

    __u32 key = 0;
    __u32 *zpid = bpf_map_lookup_elem(&zion_pid, &key);
    if (!zpid)
        return 0;

    __s64 target = ctx->target_pid;
    if ((__u32)target != *zpid)
        return 0;

    struct kill_event *evt = bpf_ringbuf_reserve(&kill_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

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
