// SPDX-License-Identifier: GPL-2.0
// XDP segmentation program for network isolation

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Configuration parameters
#define MAX_POLICIES 256
#define MAX_PORTS 1024

// Policy structure
struct policy {
    __u32 src_ip;
    __u32 dst_ip;
    __u32 src_mask;
    __u32 dst_mask;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 action; // 0=DROP, 1=ALLOW, 2=LOG
    __u8 priority;
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_POLICIES);
    __type(key, __u32);
    __type(value, struct policy);
} policies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u16);
    __type(value, __u8);
} allowed_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Statistics counters
enum {
    STAT_PACKETS_TOTAL,
    STAT_PACKETS_ALLOWED,
    STAT_PACKETS_DROPPED,
    STAT_PACKETS_LOGGED,
    STAT_MAX
};

// Helper function to check IP match
static __always_inline int ip_match(__u32 ip, __u32 target, __u32 mask) {
    return (ip & mask) == (target & mask);
}

// Helper function to get protocol
static __always_inline __u8 get_protocol(struct iphdr *iph) {
    return iph->protocol;
}

// Helper function to get ports
static __always_inline void get_ports(struct iphdr *iph, void *data_end, 
                                     __u16 *src_port, __u16 *dst_port) {
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(iph + 1);
        if ((void *)(tcp + 1) <= data_end) {
            *src_port = bpf_ntohs(tcp->source);
            *dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(iph + 1);
        if ((void *)(udp + 1) <= data_end) {
            *src_port = bpf_ntohs(udp->source);
            *dst_port = bpf_ntohs(udp->dest);
        }
    }
}

// Main XDP program
SEC("xdp")
int xdp_segmentation_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Update total packet counter
    __u32 key = STAT_PACKETS_TOTAL;
    __u64 *total = bpf_map_lookup_elem(&stats, &key);
    if (total) {
        __sync_fetch_and_add(total, 1);
    }
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }
    
    // Only handle IPv4 for now
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // Parse IP header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_DROP;
    }
    
    __u32 src_ip = bpf_ntohl(iph->saddr);
    __u32 dst_ip = bpf_ntohl(iph->daddr);
    __u8 protocol = get_protocol(iph);
    __u16 src_port = 0, dst_port = 0;
    
    get_ports(iph, data_end, &src_port, &dst_port);
    
    // Check policies
    struct policy *policy;
    __u32 policy_key = 0;
    
    // Simple policy lookup (in real implementation, use more sophisticated matching)
    policy = bpf_map_lookup_elem(&policies, &policy_key);
    if (policy) {
        // Check if packet matches policy
        if (ip_match(src_ip, policy->src_ip, policy->src_mask) &&
            ip_match(dst_ip, policy->dst_ip, policy->dst_mask) &&
            (policy->protocol == 0 || policy->protocol == protocol) &&
            (policy->src_port == 0 || policy->src_port == src_port) &&
            (policy->dst_port == 0 || policy->dst_port == dst_port)) {
            
            if (policy->action == 1) { // ALLOW
                key = STAT_PACKETS_ALLOWED;
                __u64 *allowed = bpf_map_lookup_elem(&stats, &key);
                if (allowed) {
                    __sync_fetch_and_add(allowed, 1);
                }
                return XDP_PASS;
            } else if (policy->action == 2) { // LOG
                key = STAT_PACKETS_LOGGED;
                __u64 *logged = bpf_map_lookup_elem(&stats, &key);
                if (logged) {
                    __sync_fetch_and_add(logged, 1);
                }
                // Continue processing after logging
            }
        }
    }
    
    // Check port-based rules
    __u8 *port_allowed = bpf_map_lookup_elem(&allowed_ports, &dst_port);
    if (port_allowed && *port_allowed) {
        key = STAT_PACKETS_ALLOWED;
        __u64 *allowed = bpf_map_lookup_elem(&stats, &key);
        if (allowed) {
            __sync_fetch_and_add(allowed, 1);
        }
        return XDP_PASS;
    }
    
    // Default action: DROP
    key = STAT_PACKETS_DROPPED;
    __u64 *dropped = bpf_map_lookup_elem(&stats, &key);
    if (dropped) {
        __sync_fetch_and_add(dropped, 1);
    }
    
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
