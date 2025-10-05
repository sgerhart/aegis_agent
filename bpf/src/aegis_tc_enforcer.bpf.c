// SPDX-License-Identifier: GPL-2.0
// Aegis TC Policy Enforcer eBPF Program
// Blocks network traffic using TC (Traffic Control) hooks

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// Ethernet protocol constants
#define ETH_P_IP 0x0800

// Policy map for blocked destinations
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);      // destination IP
    __type(value, __u32);    // action (0=allow, 1=block)
} blocked_destinations SEC(".maps");

// Statistics map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Helper function to check if IP is blocked
static __always_inline int is_blocked(__u32 dst_ip) {
    __u32 *action = bpf_map_lookup_elem(&blocked_destinations, &dst_ip);
    if (action && *action == 1) {
        return 1; // blocked
    }
    return 0; // allowed
}

// TC ingress hook - blocks incoming traffic
SEC("tc")
int aegis_tc_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Skip if not enough data for Ethernet header
    if (data + 14 > data_end)
        return TC_ACT_OK; // Allow if we can't parse
    
    struct ethhdr *eth = data;
    
    // Only process IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK; // Allow non-IP traffic
    
    // Skip if not enough data for IP header
    if (data + 34 > data_end)
        return TC_ACT_OK; // Allow if we can't parse
    
    struct iphdr *ip = data + 14;
    
    // Check if destination IP is blocked
    if (is_blocked(bpf_ntohl(ip->daddr))) {
        // Update stats
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&stats, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
        return TC_ACT_SHOT; // Block the packet
    }
    
    return TC_ACT_OK; // Allow the packet
}

// TC egress hook - blocks outgoing traffic
SEC("tc")
int aegis_tc_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Skip if not enough data for Ethernet header
    if (data + 14 > data_end)
        return TC_ACT_OK; // Allow if we can't parse
    
    struct ethhdr *eth = data;
    
    // Only process IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK; // Allow non-IP traffic
    
    // Skip if not enough data for IP header
    if (data + 34 > data_end)
        return TC_ACT_OK; // Allow if we can't parse
    
    struct iphdr *ip = data + 14;
    
    // Check if destination IP is blocked
    if (is_blocked(bpf_ntohl(ip->daddr))) {
        // Update stats
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&stats, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
        return TC_ACT_SHOT; // Block the packet
    }
    
    return TC_ACT_OK; // Allow the packet
}

char _license[] SEC("license") = "GPL";
