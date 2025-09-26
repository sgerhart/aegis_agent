// SPDX-License-Identifier: GPL-2.0
// AegisFlux Policy Enforcer eBPF Program
// Enforces network policies using policy_edges and allow_lpm4 maps

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// Policy edge structure for network segmentation
struct policy_edge {
    __u32 src_ip;
    __u32 dst_ip;
    __u32 src_mask;
    __u32 dst_mask;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 action; // 0=BLOCK, 1=ALLOW, 2=LOG
    __u8 priority;
    __u32 process_uid;
    __u32 process_gid;
    __u64 timestamp;
};

// LPM (Longest Prefix Match) entry for CIDR allowlists
struct allow_cidr {
    __u32 prefix_len;
    __u32 ip;
    __u8 action; // 0=BLOCK, 1=ALLOW
    __u8 priority;
    __u64 timestamp;
};

// Statistics for policy enforcement
struct policy_stats {
    __u64 total_policies;
    __u64 active_policies;
    __u64 blocked_connections;
    __u64 allowed_connections;
    __u64 logged_connections;
    __u64 policy_hits[256];
};

// Pinned maps under /sys/fs/bpf/aegis/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct policy_edge);
    __uint(pinning, PIN_GLOBAL_NS);
} policy_edges SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct allow_cidr);
    __type(value, __u8);
    __uint(pinning, PIN_GLOBAL_NS);
} allow_lpm4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
    __uint(pinning, PIN_GLOBAL_NS);
} mode SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_stats);
    __uint(pinning, PIN_GLOBAL_NS);
} policy_stats_map SEC(".maps");

// Helper function to check if an IP matches a CIDR
static __always_inline int cidr_match(__u32 ip, __u32 prefix, __u32 prefix_len) {
    __u32 mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF;
    return (ip & mask) == (prefix & mask);
}

// Helper function to check IP match with mask
static __always_inline int ip_match(__u32 ip, __u32 target, __u32 mask) {
    return (ip & mask) == (target & mask);
}

// Helper function to check port match
static __always_inline int port_match(__u16 port, __u16 target) {
    return target == 0 || port == target;
}

// Helper function to check protocol match
static __always_inline int protocol_match(__u8 protocol, __u8 target) {
    return target == 0 || protocol == target;
}

// Helper function to update statistics
static __always_inline void update_stats(__u32 stat_type, __u32 bytes) {
    __u32 key = 0;
    struct policy_stats *stats = bpf_map_lookup_elem(&policy_stats_map, &key);
    if (!stats) return;
    
    __sync_fetch_and_add(&stats->total_policies, 1);
    
    switch (stat_type) {
        case 0: // BLOCKED
            __sync_fetch_and_add(&stats->blocked_connections, 1);
            break;
        case 1: // ALLOWED
            __sync_fetch_and_add(&stats->allowed_connections, 1);
            break;
        case 2: // LOGGED
            __sync_fetch_and_add(&stats->logged_connections, 1);
            break;
    }
}

// Helper function to parse IP header
static __always_inline struct iphdr* parse_ip_header(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Check if we have enough data for Ethernet header
    if (data + sizeof(struct ethhdr) > data_end) {
        return NULL;
    }
    
    struct ethhdr *eth = data;
    
    // Check if it's an IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return NULL;
    }
    
    // Check if we have enough data for IP header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return NULL;
    }
    
    return (struct iphdr *)(data + sizeof(struct ethhdr));
}

// Helper function to get ports from IP packet
static __always_inline void get_ports(struct iphdr *iph, struct __sk_buff *skb, 
                                     __u16 *src_port, __u16 *dst_port) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
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

// Main TC ingress classifier that enforces policies
SEC("classifier")
int seg_policy_enforcer_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Parse IP header
    struct iphdr *iph = parse_ip_header(skb);
    if (!iph) {
        return TC_ACT_OK; // Not an IP packet, pass through
    }
    
    __u32 src_ip = bpf_ntohl(iph->saddr);
    __u32 dst_ip = bpf_ntohl(iph->daddr);
    __u8 protocol = iph->protocol;
    __u16 src_port = 0, dst_port = 0;
    
    get_ports(iph, skb, &src_port, &dst_port);
    
    // Check enforcement mode
    __u32 mode_key = 0;
    __u8 *mode_val = bpf_map_lookup_elem(&mode, &mode_key);
    if (!mode_val) {
        return TC_ACT_OK; // No mode set, allow
    }
    
    // If in observe mode (0), just log and allow
    if (*mode_val == 0) {
        update_stats(2, skb->len); // LOGGED
        return TC_ACT_OK;
    }
    
    // Check policy edges for blocking rules
    struct policy_edge *edge;
    __u32 edge_key = 1; // We use key 1 for our blocking rule
    
    edge = bpf_map_lookup_elem(&policy_edges, &edge_key);
    if (edge) {
        if (ip_match(src_ip, edge->src_ip, edge->src_mask) &&
            ip_match(dst_ip, edge->dst_ip, edge->dst_mask) &&
            port_match(src_port, edge->src_port) &&
            port_match(dst_port, edge->dst_port) &&
            protocol_match(protocol, edge->protocol)) {
            
            if (edge->action == 0) { // BLOCK
                update_stats(0, skb->len); // BLOCKED
                return TC_ACT_SHOT; // Drop the packet
            } else if (edge->action == 1) { // ALLOW
                update_stats(1, skb->len); // ALLOWED
                return TC_ACT_OK;
            }
        }
    }
    
    // Check allow CIDRs
    struct allow_cidr cidr_key = {};
    cidr_key.prefix_len = 0;
    cidr_key.ip = 0;
    
    __u8 *allow_val = bpf_map_lookup_elem(&allow_lpm4, &cidr_key);
    if (allow_val && *allow_val == 1) {
        update_stats(1, skb->len); // ALLOWED
        return TC_ACT_OK;
    }
    
    // Default: allow if no specific blocking rule
    update_stats(1, skb->len); // ALLOWED
    return TC_ACT_OK;
}

// Cgroup egress program for outbound connections
SEC("cgroup/connect4")
int seg_policy_enforcer_egress(struct bpf_sock_addr *ctx)
{
    __u32 src_ip = ctx->user_ip4;
    __u32 dst_ip = ctx->user_port >> 16;
    __u16 dst_port = ctx->user_port & 0xFFFF;
    
    // Check enforcement mode
    __u32 mode_key = 0;
    __u8 *mode_val = bpf_map_lookup_elem(&mode, &mode_key);
    if (!mode_val) {
        return 1; // No mode set, allow
    }
    
    // If in observe mode (0), just log and allow
    if (*mode_val == 0) {
        update_stats(2, 0); // LOGGED
        return 1; // ALLOW
    }
    
    // Check policy edges for blocking rules
    struct policy_edge *edge;
    __u32 edge_key = 1; // We use key 1 for our blocking rule
    
    edge = bpf_map_lookup_elem(&policy_edges, &edge_key);
    if (edge) {
        if (ip_match(src_ip, edge->src_ip, edge->src_mask) &&
            ip_match(dst_ip, edge->dst_ip, edge->dst_mask) &&
            port_match(0, edge->src_port) &&
            port_match(dst_port, edge->dst_port) &&
            protocol_match(IPPROTO_TCP, edge->protocol)) {
            
            if (edge->action == 0) { // BLOCK
                update_stats(0, 0); // BLOCKED
                return 0; // DENY
            } else if (edge->action == 1) { // ALLOW
                update_stats(1, 0); // ALLOWED
                return 1; // ALLOW
            }
        }
    }
    
    // Check allow CIDRs
    struct allow_cidr cidr_key = {};
    cidr_key.prefix_len = 0;
    cidr_key.ip = 0;
    
    __u8 *allow_val = bpf_map_lookup_elem(&allow_lpm4, &cidr_key);
    if (allow_val && *allow_val == 1) {
        update_stats(1, 0); // ALLOWED
        return 1; // ALLOW
    }
    
    // Default: allow if no specific blocking rule
    update_stats(1, 0); // ALLOWED
    return 1; // ALLOW
}

char _license[] SEC("license") = "GPL";


