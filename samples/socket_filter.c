#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct bpf_map_def SEC("maps") ip_count = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),    // IP address
    .value_size = sizeof(__u32),  // packet count
    .max_entries = 10000,
    .flags = 0,
};

SEC("socket")
int filter_tcp(struct __sk_buff *skb) {
    // Check Ethernet header
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    
    if (data + sizeof(*eth) > data_end)
        return 0;  // Invalid packet size
        
    // Check IP header
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;  // Not IP
        
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;  // Invalid IP header
        
    // Track source IP addresses
    __u32 src_ip = ip->saddr;
    __u32 *count = bpf_map_lookup_elem(&ip_count, &src_ip);
    if (count) 
        __sync_fetch_and_add(count, 1);
    else {
        __u32 init_val = 1;
        bpf_map_update_elem(&ip_count, &src_ip, &init_val, BPF_ANY);
    }
    
    return skb->len;  // Accept all packets
}