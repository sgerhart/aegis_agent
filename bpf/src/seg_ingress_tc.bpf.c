// SPDX-License-Identifier: GPL-2.0
// AegisFlux Segmentation Ingress TC Program
// Monitors and controls inbound traffic at the TC ingress level

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Configuration
#define MAX_POLICIES 256
#define MAX_FILTERS 512
#define MAX_CLASSES 64

// Traffic class structure
struct traffic_class {
    __u32 class_id;
    __u32 rate;      // bytes per second
    __u32 burst;     // burst size
    __u8 priority;
    __u8 action;     // 0=PASS, 1=DROP, 2=MARK, 3=REDIRECT
    __u32 mark_value;
    __u32 redirect_ifindex;
};

// Filter structure for traffic classification
struct traffic_filter {
    __u32 src_ip;
    __u32 dst_ip;
    __u32 src_mask;
    __u32 dst_mask;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 class_id;
    __u8 action;
    __u8 priority;
};

// Statistics structure
struct tc_stats {
    __u64 total_packets;
    __u64 passed_packets;
    __u64 dropped_packets;
    __u64 marked_packets;
    __u64 redirected_packets;
    __u64 total_bytes;
    __u64 class_stats[MAX_CLASSES];
    __u64 filter_hits[MAX_FILTERS];
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CLASSES);
    __type(key, __u32);
    __type(value, struct traffic_class);
} traffic_classes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FILTERS);
    __type(key, __u32);
    __type(value, struct traffic_filter);
} traffic_filters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tc_stats);
} tc_stats_map SEC(".maps");

// Helper function to check IP match
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
static __always_inline void update_stats(__u32 stat_type, __u32 class_id, __u32 filter_id, __u32 bytes) {
    __u32 key = 0;
    struct tc_stats *stats = bpf_map_lookup_elem(&tc_stats_map, &key);
    if (!stats) return;
    
    __sync_fetch_and_add(&stats->total_packets, 1);
    __sync_fetch_and_add(&stats->total_bytes, bytes);
    
    switch (stat_type) {
        case 0: // PASS
            __sync_fetch_and_add(&stats->passed_packets, 1);
            break;
        case 1: // DROP
            __sync_fetch_and_add(&stats->dropped_packets, 1);
            break;
        case 2: // MARK
            __sync_fetch_and_add(&stats->marked_packets, 1);
            break;
        case 3: // REDIRECT
            __sync_fetch_and_add(&stats->redirected_packets, 1);
            break;
    }
    
    if (class_id < MAX_CLASSES) {
        __sync_fetch_and_add(&stats->class_stats[class_id], 1);
    }
    
    if (filter_id < MAX_FILTERS) {
        __sync_fetch_and_add(&stats->filter_hits[filter_id], 1);
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

// Main TC ingress classifier
SEC("classifier")
int seg_ingress_cls(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Update total packet counter
    update_stats(0, 0, 0, skb->len);
    
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
    
    // Apply traffic filters
    struct traffic_filter *filter;
    __u32 filter_key = 0;
    
    // Simple filter lookup (in real implementation, use more sophisticated matching)
    filter = bpf_map_lookup_elem(&traffic_filters, &filter_key);
    if (filter) {
        if (ip_match(src_ip, filter->src_ip, filter->src_mask) &&
            ip_match(dst_ip, filter->dst_ip, filter->dst_mask) &&
            port_match(src_port, filter->src_port) &&
            port_match(dst_port, filter->dst_port) &&
            protocol_match(protocol, filter->protocol)) {
            
            // Get traffic class
            struct traffic_class *tc;
            __u32 class_key = filter->class_id;
            tc = bpf_map_lookup_elem(&traffic_classes, &class_key);
            
            if (tc) {
                if (tc->action == 1) { // DROP
                    update_stats(1, class_key, filter_key, skb->len);
                    return TC_ACT_SHOT;
                } else if (tc->action == 2) { // MARK
                    bpf_skb_set_tc_index(skb, tc->mark_value);
                    update_stats(2, class_key, filter_key, skb->len);
                } else if (tc->action == 3) { // REDIRECT
                    if (tc->redirect_ifindex != 0) {
                        bpf_skb_redirect(skb, tc->redirect_ifindex, 0);
                        update_stats(3, class_key, filter_key, skb->len);
                        return TC_ACT_REDIRECT;
                    }
                }
            }
        }
    }
    
    // Default action: PASS
    update_stats(0, 0, 0, skb->len);
    return TC_ACT_OK;
}

// TC ingress action program
SEC("action")
int seg_ingress_action(struct __sk_buff *skb) {
    // This program can be used for additional packet processing
    // after classification, such as packet modification or logging
    
    // Example: Log packet information
    struct iphdr *iph = parse_ip_header(skb);
    if (iph) {
        // In a real implementation, you might log packet details
        // or perform additional processing here
    }
    
    return TC_ACT_OK;
}

// Helper program for traffic monitoring
SEC("kprobe/dev_queue_xmit")
int trace_dev_queue_xmit(struct pt_regs *ctx) {
    // This can be used to monitor traffic patterns
    // and update statistics
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
