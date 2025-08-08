/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* Helper functions called from eBPF programs */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *) 1;
static int (*bpf_map_update_elem)(void *map, const void *key, const void *value,
				 unsigned long long flags) =
	(void *) 2;
static int (*bpf_map_delete_elem)(void *map, const void *key) =
	(void *) 3;
static int (*bpf_probe_read)(void *dst, int size, const void *unsafe_ptr) =
	(void *) 4;
static unsigned long long (*bpf_ktime_get_ns)(void) =
	(void *) 5;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) 6;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
	(void *) 14;
static unsigned long long (*bpf_get_current_uid_gid)(void) =
	(void *) 15;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
	(void *) 16;
static int (*bpf_perf_event_output)(void *ctx, void *map,
				  unsigned long long flags, void *data,
				  int size) =
	(void *) 25;

/* Attach type definitions */
#define BPF_CGROUP_INET_INGRESS	0
#define BPF_CGROUP_INET_EGRESS	1

/* Map type definitions */
#define BPF_MAP_TYPE_UNSPEC		0
#define BPF_MAP_TYPE_HASH		1
#define BPF_MAP_TYPE_ARRAY		2
#define BPF_MAP_TYPE_PROG_ARRAY		3
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY	4

/* Map flags */
#define BPF_F_NO_PREALLOC	(1U << 0)
#define BPF_F_NO_COMMON_LRU	(1U << 1)
#define BPF_F_NUMA_NODE		(1U << 2)
#define BPF_F_RDONLY		(1U << 3)
#define BPF_F_WRONLY		(1U << 4)

/* Program types */
#define BPF_PROG_TYPE_UNSPEC		0
#define BPF_PROG_TYPE_SOCKET_FILTER	1
#define BPF_PROG_TYPE_KPROBE		2
#define BPF_PROG_TYPE_XDP		3

/* Return values */
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

/* Convenience macros */
#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif

#ifndef SEC
# define SEC(NAME)                        \
   __section(NAME)
#endif

#endif /* __BPF_HELPERS_H */