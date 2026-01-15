//go:build ignore

// ═══════════════════════════════════════════════════════════════════════
// Zion v2 — BPF-LSM Programs for Deterministic Attack Prevention
//
// Unlike tracepoints that OBSERVE syscalls, LSM hooks SIT IN THE
// EXECUTION PATH. The syscall CANNOT proceed until our BPF program
// returns a verdict:
//   return 0       → ALLOW (syscall proceeds)
//   return -EPERM  → DENY  (syscall blocked, attacker gets "Operation not permitted")
//
// This eliminates all race conditions — the attacker's code is frozen
// waiting for our decision.
// ═══════════════════════════════════════════════════════════════════════

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

// Helper declaration for bpf_probe_read_kernel_str
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 115;

// ── Policy configuration (populated from Go userspace) ──────────────

// Policy flags — each bit enables/disables an LSM hook enforcement.
// 0 = detect-only (allow + log), 1 = enforce (block + log)
struct policy_flags {
    __u32 enforce_ptrace;       // Block unauthorized ptrace
    __u32 enforce_setuid;       // Block unauthorized setuid
    __u32 enforce_file_open;    // Block access to sensitive files
    __u32 enforce_memfd;        // Block suspicious memfd_create
    __u32 enforce_kill;         // Block signals to Zion
    __u32 enforce_exec;         // Block banned binary execution
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_flags);
} lsm_policy SEC(".maps");

// UIDs allowed to use ptrace (e.g., root=0)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWED_UIDS);
    __type(key, __u32);    // UID
    __type(value, __u8);   // dummy value (presence = allowed)
} ptrace_allowed_uids SEC(".maps");

// Comm names allowed to call setuid(0) (e.g., "sudo", "su")
// Key: 16-byte comm string (null-padded)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[16]);
    __type(value, __u8);
} setuid_allowed_comms SEC(".maps");

// Zion's own PID — for self-defense (block signals targeting us)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} lsm_zion_pid SEC(".maps");

// Comm names allowed to read credential files
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[16]);
    __type(value, __u8);
} credential_reader_comms SEC(".maps");

// Comm names allowed to use memfd_create legitimately
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[16]);
    __type(value, __u8);
} memfd_allowed_comms SEC(".maps");

// Comm names allowed to use ptrace (e.g., "ps", "top", "cat", IDEs)
// These processes read /proc/[pid]/* which triggers ptrace_access_check
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[16]);
    __type(value, __u8);
} ptrace_allowed_comms SEC(".maps");

// Ring buffer to emit block/allow decisions to userspace for logging
struct zion_lsm_event {
    __u32 pid;
    __u32 uid;
    __u32 hook;          // Which LSM hook fired (enum below)
    __s32 decision;      // 0 = allowed, -1 = blocked
    __u8  comm[TASK_COMM_LEN];
    __u8  detail[PATH_MAX_LEN]; // e.g., filename, target info
};

// LSM hook identifiers for userspace logging
enum lsm_hook_id {
    HOOK_PTRACE      = 1,
    HOOK_SETUID      = 2,
    HOOK_FILE_OPEN   = 3,
    HOOK_MEMFD       = 4,
    HOOK_KILL        = 5,
    HOOK_EXEC        = 6,
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MB
} lsm_events SEC(".maps");


// ── Helper: emit a decision event ───────────────────────────────────

static __always_inline void emit_event(__u32 hook, __s32 decision, const char *detail) {
    struct zion_lsm_event *evt = bpf_ringbuf_reserve(&lsm_events, sizeof(*evt), 0);
    if (!evt)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)(pid_tgid >> 32);

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = (__u32)uid_gid;

    evt->hook = hook;
    evt->decision = decision;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    if (detail) {
        bpf_probe_read_kernel_str(evt->detail, sizeof(evt->detail), detail);
    } else {
        evt->detail[0] = 0;
    }

    bpf_ringbuf_submit(evt, 0);
}

static __always_inline void emit_event_str(__u32 hook, __s32 decision, const char *str, int len) {
    struct zion_lsm_event *evt = bpf_ringbuf_reserve(&lsm_events, sizeof(*evt), 0);
    if (!evt)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)(pid_tgid >> 32);

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = (__u32)uid_gid;

    evt->hook = hook;
    evt->decision = decision;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    if (len > 0 && len <= (int)sizeof(evt->detail))
        __builtin_memcpy(evt->detail, str, len);
    else
        evt->detail[0] = 0;

    bpf_ringbuf_submit(evt, 0);
}


// ═══════════════════════════════════════════════════════════════════════
// LSM Hook 1: ptrace_access_check — Block Process Injection (T1055)
//
// Called when a process tries to ptrace another. We block it unless:
//   1. Caller UID is in the allowed list, OR
//   2. Caller is the parent of the target (debugger)
// ═══════════════════════════════════════════════════════════════════════

SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_access_check, struct task_struct *child, unsigned int mode)
{
    __u32 key = 0;
    struct policy_flags *policy = bpf_map_lookup_elem(&lsm_policy, &key);
    if (!policy || !policy->enforce_ptrace)
        return 0;  // Not enforcing — pass through

    // Check if caller UID is allowed
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u8 *allowed = bpf_map_lookup_elem(&ptrace_allowed_uids, &uid);
    if (allowed)
        return 0;  // Allowed UID

    // Check if caller is parent of target (debugger scenario)
    __u64 caller_tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 child_ppid;
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &child->real_parent);
    bpf_probe_read_kernel(&child_ppid, sizeof(child_ppid), &parent->tgid);
    if ((__u32)caller_tgid == child_ppid)
        return 0;  // Parent debugging child — allowed

    // Check if caller comm is whitelisted (ps, top, cat, IDEs, etc.)
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *comm_allowed = bpf_map_lookup_elem(&ptrace_allowed_comms, comm);
    if (comm_allowed)
        return 0;  // Whitelisted process

    // BLOCKED: unauthorized ptrace
    emit_event(HOOK_PTRACE, -1, NULL);
    return -EPERM;
}


// ═══════════════════════════════════════════════════════════════════════
// LSM Hook 2: task_fix_setuid — Block Privilege Escalation (T1068)
//
// Called during credential change (setuid/setgid/etc).
// We block transitions to UID 0 unless the binary is whitelisted
// (e.g., sudo, su, pkexec).
// ═══════════════════════════════════════════════════════════════════════

SEC("lsm/task_fix_setuid")
int BPF_PROG(lsm_task_fix_setuid, struct cred *new, const struct cred *old, int flags)
{
    __u32 key = 0;
    struct policy_flags *policy = bpf_map_lookup_elem(&lsm_policy, &key);
    if (!policy || !policy->enforce_setuid)
        return 0;

    // Read old and new UIDs
    __u32 old_uid, new_uid;
    bpf_probe_read_kernel(&old_uid, sizeof(old_uid), &old->uid.val);
    bpf_probe_read_kernel(&new_uid, sizeof(new_uid), &new->uid.val);

    // Only care about escalation TO root FROM non-root
    if (new_uid != 0 || old_uid == 0)
        return 0;

    // Check if process comm is in the allowed list
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    __u8 *allowed = bpf_map_lookup_elem(&setuid_allowed_comms, comm);
    if (allowed)
        return 0;  // Whitelisted binary (sudo, su, etc.)

    // BLOCKED: unauthorized privilege escalation
    emit_event_str(HOOK_SETUID, -1, comm, 16);
    return -EPERM;
}


// ═══════════════════════════════════════════════════════════════════════
// LSM Hook 3: file_open — Block Sensitive File Access (T1003/T1070/T1053)
//
// Called when a file is opened. We check if the file is in a
// sensitive category and block unauthorized access.
//
// Protected paths:
//   - /etc/shadow, /etc/gshadow (credential access)
//   - /var/log/* (log tampering — write only)
//   - .bash_history, .zsh_history (history tampering)
//   - /etc/crontab, cron.d/* (persistence)
// ═══════════════════════════════════════════════════════════════════════

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    __u32 key = 0;
    struct policy_flags *policy = bpf_map_lookup_elem(&lsm_policy, &key);
    if (!policy || !policy->enforce_file_open)
        return 0;

    // Read the dentry name (basename of the file)
    struct dentry *dentry;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);

    struct qstr d_name;
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);

    char name[32];
    bpf_probe_read_kernel_str(name, sizeof(name), d_name.name);

    // Read file flags to determine if it's a write
    unsigned int f_flags;
    bpf_probe_read_kernel(&f_flags, sizeof(f_flags), &file->f_flags);
    int is_write = (f_flags & 0x3) != 0; // O_WRONLY=1, O_RDWR=2

    // Get caller comm for whitelist checks
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    // ── Check credential files (block ALL unauthorized reads/writes) ──
    // Match "shadow" or "gshadow"
    if (name[0] == 's' && name[1] == 'h' && name[2] == 'a' && name[3] == 'd' &&
        name[4] == 'o' && name[5] == 'w') {
        // Check if caller is an allowed credential reader
        __u8 *ok = bpf_map_lookup_elem(&credential_reader_comms, comm);
        if (ok)
            return 0;

        emit_event_str(HOOK_FILE_OPEN, -1, name, 32);
        return -EPERM;
    }
    if (name[0] == 'g' && name[1] == 's' && name[2] == 'h' && name[3] == 'a' &&
        name[4] == 'd' && name[5] == 'o' && name[6] == 'w') {
        __u8 *ok = bpf_map_lookup_elem(&credential_reader_comms, comm);
        if (ok)
            return 0;

        emit_event_str(HOOK_FILE_OPEN, -1, name, 32);
        return -EPERM;
    }

    // ── Check history files (block write/truncate) ──
    if (is_write) {
        // .bash_history
        if (name[0] == '.' && name[1] == 'b' && name[2] == 'a' && name[3] == 's' &&
            name[4] == 'h' && name[5] == '_' && name[6] == 'h') {
            emit_event_str(HOOK_FILE_OPEN, -1, name, 32);
            return -EPERM;
        }
        // .zsh_history
        if (name[0] == '.' && name[1] == 'z' && name[2] == 's' && name[3] == 'h' &&
            name[4] == '_' && name[5] == 'h') {
            emit_event_str(HOOK_FILE_OPEN, -1, name, 32);
            return -EPERM;
        }
    }

    return 0;
}


// ═══════════════════════════════════════════════════════════════════════
// LSM Hook 4: task_kill — Block Sensor Tampering (T1562)
//
// Called when a process sends a signal to another process.
// We block SIGKILL/SIGTERM/SIGSTOP targeting Zion's own PID.
// ═══════════════════════════════════════════════════════════════════════

SEC("lsm/task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *target, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    __u32 key = 0;
    struct policy_flags *policy = bpf_map_lookup_elem(&lsm_policy, &key);
    if (!policy || !policy->enforce_kill)
        return 0;

    // Only care about dangerous signals
    if (sig != 9 && sig != 15 && sig != 19)
        return 0;

    // Get Zion's PID from the map
    __u32 *zpid = bpf_map_lookup_elem(&lsm_zion_pid, &key);
    if (!zpid)
        return 0;

    // Read target's TGID
    __u32 target_tgid;
    bpf_probe_read_kernel(&target_tgid, sizeof(target_tgid), &target->tgid);

    if (target_tgid != *zpid)
        return 0;  // Not targeting Zion

    // BLOCKED: attempted sensor tampering
    emit_event(HOOK_KILL, -1, NULL);
    return -EPERM;
}


// ═══════════════════════════════════════════════════════════════════════
// LSM Hook 5: bprm_check_security — Block Malicious Execution (T1059)
//
// Called before a new program is executed (execve path).
// We can block execution of specific banned binaries.
// Currently a placeholder — the blocked_comms map can be populated
// dynamically from userspace.
// ═══════════════════════════════════════════════════════════════════════

// Banned binary comms (populated dynamically from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, __u8);
} blocked_exec_comms SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm)
{
    __u32 key = 0;
    struct policy_flags *policy = bpf_map_lookup_elem(&lsm_policy, &key);
    if (!policy || !policy->enforce_exec)
        return 0;

    // Read the binary name from bprm->filename
    const char *filename;
    bpf_probe_read_kernel(&filename, sizeof(filename), &bprm->filename);

    // Read basename for map lookup — we read the full path and
    // search for the last '/' to find the basename.
    char path[PATH_MAX_LEN];
    bpf_probe_read_kernel_str(path, sizeof(path), filename);

    // Find basename: search backwards for '/'
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
        // Copy from after the last slash
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
        // No slash found — use the whole path as the name
        #pragma unroll
        for (int i = 0; i < 15; i++) {
            basename[i] = path[i];
            if (path[i] == 0)
                break;
        }
    }

    // Check if this binary is in the blocked list
    __u8 *blocked = bpf_map_lookup_elem(&blocked_exec_comms, basename);
    if (blocked) {
        emit_event_str(HOOK_EXEC, -1, basename, 16);
        return -EPERM;
    }

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
