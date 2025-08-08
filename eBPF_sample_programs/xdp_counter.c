#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
// Protocol numbers and flags
#define __always_inline inline __attribute__((always_inline))
#define IP_OFFSET 0x1FFF  // Fragment offset field
#define IPPROTO_ICMP  1
#define IPPROTO_TCP   6
#define IPPROTO_UDP  17

// Map to store per-protocol packet counts
struct bpf_map_def SEC("maps") protocol_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u8),     // Protocol number
    .value_size = sizeof(__u64),  // Packet count
    .max_entries = 256,           // Max number of protocols
    .flags = 0,
};

// Map to store dropped packet counts per protocol
struct bpf_map_def SEC("maps") drop_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u8),     // Protocol number
    .value_size = sizeof(__u64),  // Drop count
    .max_entries = 256,           // Max number of protocols
    .flags = 0,
};

// Map for protocol drop policy
struct bpf_map_def SEC("maps") drop_policy = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u8),     // Protocol number
    .value_size = sizeof(__u8),   // Drop flag (1 = drop)
    .max_entries = 256,           // Max number of protocols
    .flags = 0,
};

static __always_inline
int update_stats(struct bpf_map_def *map, __u8 protocol) {
    __u64 *count = bpf_map_lookup_elem(map, &protocol);
    __u64 init_val = 1;

    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        bpf_map_update_elem(map, &protocol, &init_val, BPF_ANY);
    }
    return 0;
}

SEC("xdp")
int xdp_packet_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_DROP;  // Invalid Ethernet header

    // Only handle IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;  // Non-IPv4 packet

    // Parse IP header
    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return XDP_DROP;  // Invalid IP header

    // Update protocol statistics
    update_stats(&protocol_stats, iph->protocol);

    // Check drop policy
    __u8 *should_drop = bpf_map_lookup_elem(&drop_policy, &iph->protocol);
    if (should_drop && *should_drop) {
        // Update drop statistics
        update_stats(&drop_stats, iph->protocol);
        return XDP_DROP;
    }

    // Additional checks based on protocol
    switch (iph->protocol) {
        case IPPROTO_TCP:
            // Drop if fragment (not first fragment)
            if (iph->frag_off & htons(IP_OFFSET))
                return XDP_DROP;
            break;
            
        case IPPROTO_UDP:
            // Drop if TTL too low
            if (iph->ttl < 10) {
                update_stats(&drop_stats, iph->protocol);
                return XDP_DROP;
            }
            break;

        case IPPROTO_ICMP:
            // Allow all ICMP
            break;

        default:
            // Drop unknown protocols
            update_stats(&drop_stats, iph->protocol);
            return XDP_DROP;
    }

    return XDP_PASS;
}