//go:build ignore

// zion_lsm.c — BPF-LSM enforcement hooks
// Blocks malicious syscalls synchronously in-kernel (return -EPERM).
// Policy maps are populated from Go userspace at startup.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM   1
#define NULL    ((void *)0)
#define TASK_COMM_LEN 64
#define PATH_MAX_LEN  64
#define MAX_BLOCKED_HASHES 256
#define MAX_ALLOWED_UIDS   64

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 115;

// --- Policy flags (0 = detect-only, 1 = enforce) ---

struct policy_flags {
    __u32 enforce_ptrace;
    __u32 enforce_setuid;
    __u32 enforce_file_open;
    __u32 enforce_memfd;
    __u32 enforce_kill;
    __u32 enforce_exec;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_flags);
} lsm_policy SEC(".maps");

// --- Whitelist maps (populated from config.yaml via Go) ---

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWED_UIDS);
    __type(key, __u32);
    __type(value, __u8);
} ptrace_allowed_uids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[16]);
    __type(value, __u8);
} ptrace_allowed_comms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[16]);
    __type(value, __u8);
} setuid_allowed_comms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} lsm_zion_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[16]);
    __type(value, __u8);
} credential_reader_comms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[16]);
    __type(value, __u8);
} memfd_allowed_comms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, __u8);
} blocked_exec_comms SEC(".maps");

// --- Event ring buffer ---

struct zion_lsm_event {
    __u32 pid;
    __u32 uid;
    __u32 hook;
    __s32 decision;     // 0 = allowed, -1 = blocked
    __u8  comm[TASK_COMM_LEN];
    __u8  detail[PATH_MAX_LEN];
};

enum lsm_hook_id {
    HOOK_PTRACE    = 1,
    HOOK_SETUID    = 2,
    HOOK_FILE_OPEN = 3,
    HOOK_MEMFD     = 4,
    HOOK_KILL      = 5,
    HOOK_EXEC      = 6,
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} lsm_events SEC(".maps");

// --- Helpers ---

static __always_inline void emit_event(__u32 hook, __s32 decision, const char *detail) {
    struct zion_lsm_event *evt = bpf_ringbuf_reserve(&lsm_events, sizeof(*evt), 0);
    if (!evt)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)(pid_tgid >> 32);
    evt->uid = (__u32)bpf_get_current_uid_gid();
    evt->hook = hook;
    evt->decision = decision;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    if (detail)
        bpf_probe_read_kernel_str(evt->detail, sizeof(evt->detail), detail);
    else
        evt->detail[0] = 0;

    bpf_ringbuf_submit(evt, 0);
}

static __always_inline void emit_event_str(__u32 hook, __s32 decision, const char *str, int len) {
    struct zion_lsm_event *evt = bpf_ringbuf_reserve(&lsm_events, sizeof(*evt), 0);
    if (!evt)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)(pid_tgid >> 32);
    evt->uid = (__u32)bpf_get_current_uid_gid();
    evt->hook = hook;
    evt->decision = decision;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    if (len > 0 && len <= (int)sizeof(evt->detail))
        __builtin_memcpy(evt->detail, str, len);
    else
        evt->detail[0] = 0;

    bpf_ringbuf_submit(evt, 0);
}

// --- LSM Hook: ptrace_access_check (T1055) ---
// Block non-whitelisted ptrace. Allow: root UIDs, parent→child, whitelisted comms.

SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_access_check, struct task_struct *child, unsigned int mode)
{
    __u32 key = 0;
    struct policy_flags *policy = bpf_map_lookup_elem(&lsm_policy, &key);
    if (!policy || !policy->enforce_ptrace)
        return 0;

    __u32 uid = (__u32)bpf_get_current_uid_gid();
    if (bpf_map_lookup_elem(&ptrace_allowed_uids, &uid))
        return 0;

    // Allow parent debugging child
    __u64 caller_tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 child_ppid;
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &child->real_parent);
    bpf_probe_read_kernel(&child_ppid, sizeof(child_ppid), &parent->tgid);
    if ((__u32)caller_tgid == child_ppid)
        return 0;

    // Allow whitelisted comms (ps, top, IDEs, etc.)
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (bpf_map_lookup_elem(&ptrace_allowed_comms, comm))
        return 0;

    emit_event(HOOK_PTRACE, -1, NULL);
    return -EPERM;
}

// --- LSM Hook: task_fix_setuid (T1068) ---
// Block non-root → root transitions unless comm is whitelisted (sudo, su, etc.)

SEC("lsm/task_fix_setuid")
int BPF_PROG(lsm_task_fix_setuid, struct cred *new, const struct cred *old, int flags)
{
    __u32 key = 0;
    struct policy_flags *policy = bpf_map_lookup_elem(&lsm_policy, &key);
    if (!policy || !policy->enforce_setuid)
        return 0;

    __u32 old_uid, new_uid;
    bpf_probe_read_kernel(&old_uid, sizeof(old_uid), &old->uid.val);
    bpf_probe_read_kernel(&new_uid, sizeof(new_uid), &new->uid.val);

    if (new_uid != 0 || old_uid == 0)
        return 0;

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (bpf_map_lookup_elem(&setuid_allowed_comms, comm))
        return 0;

    emit_event_str(HOOK_SETUID, -1, comm, 16);
    return -EPERM;
}

// --- LSM Hook: file_open (T1003/T1070/T1053) ---
// Block access to: shadow/gshadow (creds), .bash_history/.zsh_history (evasion)

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    __u32 key = 0;
    struct policy_flags *policy = bpf_map_lookup_elem(&lsm_policy, &key);
    if (!policy || !policy->enforce_file_open)
        return 0;

    struct dentry *dentry;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);

    struct qstr d_name;
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);

    char name[32];
    bpf_probe_read_kernel_str(name, sizeof(name), d_name.name);

    unsigned int f_flags;
    bpf_probe_read_kernel(&f_flags, sizeof(f_flags), &file->f_flags);
    int is_write = (f_flags & 0x3) != 0;

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    // Credential files: shadow, gshadow
    if (name[0] == 's' && name[1] == 'h' && name[2] == 'a' && name[3] == 'd' &&
        name[4] == 'o' && name[5] == 'w') {
        if (bpf_map_lookup_elem(&credential_reader_comms, comm))
            return 0;
        emit_event_str(HOOK_FILE_OPEN, -1, name, 32);
        return -EPERM;
    }
    if (name[0] == 'g' && name[1] == 's' && name[2] == 'h' && name[3] == 'a' &&
        name[4] == 'd' && name[5] == 'o' && name[6] == 'w') {
        if (bpf_map_lookup_elem(&credential_reader_comms, comm))
            return 0;
        emit_event_str(HOOK_FILE_OPEN, -1, name, 32);
        return -EPERM;
    }

    // History files: block writes to .bash_history, .zsh_history
    if (is_write) {
        if (name[0] == '.' && name[1] == 'b' && name[2] == 'a' && name[3] == 's' &&
            name[4] == 'h' && name[5] == '_' && name[6] == 'h') {
            emit_event_str(HOOK_FILE_OPEN, -1, name, 32);
            return -EPERM;
        }
        if (name[0] == '.' && name[1] == 'z' && name[2] == 's' && name[3] == 'h' &&
            name[4] == '_' && name[5] == 'h') {
            emit_event_str(HOOK_FILE_OPEN, -1, name, 32);
            return -EPERM;
        }
    }

    return 0;
}

// --- LSM Hook: task_kill (T1562) ---
// Block SIGKILL/SIGTERM/SIGSTOP targeting Zion's PID.

SEC("lsm/task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *target, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    __u32 key = 0;
    struct policy_flags *policy = bpf_map_lookup_elem(&lsm_policy, &key);
    if (!policy || !policy->enforce_kill)
        return 0;

    if (sig != 9 && sig != 15 && sig != 19)
        return 0;

    __u32 *zpid = bpf_map_lookup_elem(&lsm_zion_pid, &key);
    if (!zpid)
        return 0;

    __u32 target_tgid;
    bpf_probe_read_kernel(&target_tgid, sizeof(target_tgid), &target->tgid);

    if (target_tgid != *zpid)
        return 0;

    emit_event(HOOK_KILL, -1, NULL);
    return -EPERM;
}

// --- LSM Hook: bprm_check_security (T1059) ---
// Block execution of binaries in the blocked_exec_comms map.

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm)
{
    __u32 key = 0;
    struct policy_flags *policy = bpf_map_lookup_elem(&lsm_policy, &key);
    if (!policy || !policy->enforce_exec)
        return 0;

    const char *filename;
    bpf_probe_read_kernel(&filename, sizeof(filename), &bprm->filename);

    char path[PATH_MAX_LEN];
    bpf_probe_read_kernel_str(path, sizeof(path), filename);

    // Extract basename
    int last_slash = -1;
    #pragma unroll
    for (int i = 0; i < PATH_MAX_LEN - 1; i++) {
        if (path[i] == 0)
            break;
        if (path[i] == '/')
            last_slash = i;
    }

    char basename[16] = {};
    if (last_slash >= 0 && last_slash < PATH_MAX_LEN - 1) {
        int src = last_slash + 1;
        #pragma unroll
        for (int i = 0; i < 15; i++) {
            if (src + i >= PATH_MAX_LEN)
                break;
            basename[i] = path[src + i];
            if (path[src + i] == 0)
                break;
        }
    } else {
        #pragma unroll
        for (int i = 0; i < 15; i++) {
            basename[i] = path[i];
            if (path[i] == 0)
                break;
        }
    }

    if (bpf_map_lookup_elem(&blocked_exec_comms, basename)) {
        emit_event_str(HOOK_EXEC, -1, basename, 16);
        return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
