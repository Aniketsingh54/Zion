//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// zion_status — single-element counter proving the probe is alive.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} zion_status SEC(".maps");

// Fires on every syscall entry; bumps the counter atomically.
SEC("tracepoint/raw_syscalls/sys_enter")
int zion_probe(void *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&zion_status, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
