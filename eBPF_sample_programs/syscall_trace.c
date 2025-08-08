#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
};

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 128,
};

SEC("kprobe/sys_execve")
int trace_execve(struct pt_regs *ctx) {
    struct event e = {};
    
    // Get process info
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // Send event to userspace
    bpf_perf_event_output(ctx, &events, 0, &e, sizeof(e));
    
    return 0;
}