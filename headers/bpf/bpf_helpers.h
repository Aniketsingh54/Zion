/*
 * Minimal vendored BPF helpers — avoids system dependency on libbpf-dev.
 * Contains only the macros and helper declarations Zion needs.
 */
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

/* Section attribute for eBPF programs and maps */
#define SEC(name) __attribute__((section(name), used))

/* BTF-defined map declaration macros */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/*
 * BPF helper functions — declared as function pointers initialized
 * to the helper ID. The kernel's verifier replaces these at load time.
 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)4;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)16;
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *)25;

/* Ring buffer helpers (kernel 5.8+) */
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

/* Task/process helpers */
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static __u64 (*bpf_get_current_task)(void) = (void *)35;

#endif /* __BPF_HELPERS__ */
