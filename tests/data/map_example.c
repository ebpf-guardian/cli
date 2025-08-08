#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u32);
} my_map SEC(".maps");

SEC("kprobe/sys_open")
int trace_open(struct pt_regs *ctx) {
    __u32 key = 1;
    __u32 value = 42;
    bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);
    return 0;
}