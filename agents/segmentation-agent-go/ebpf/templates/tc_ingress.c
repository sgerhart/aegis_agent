// SPDX-License-Identifier: GPL-2.0
// TC ingress program for traffic control and segmentation

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Configuration
#define MAX_CLASSES 64
#define MAX_FILTERS 256

// Traffic class structure
struct traffic_class {
    __u32 class_id;
    __u32 rate;      // bytes per second
    __u32 burst;     // burst size
    __u8 priority;
    __u8 action;     // 0=PASS, 1=DROP, 2=MARK
    __u32 mark_value;
};

// Filter structure
struct filter {
    __u32 src_ip;
    __u32 dst_ip;
    __u32 src_mask;
    __u32 dst_mask;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 class_id;
    __u8 action;
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
    __type(value, struct filter);
} filters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} tc_stats SEC(".maps");

// Statistics
enum {
    TC_STAT_PACKETS_TOTAL,
    TC_STAT_PACKETS_PASSED,
    TC_STAT_PACKETS_DROPPED,
    TC_STAT_PACKETS_MARKED,
    TC_STAT_BYTES_TOTAL,
    TC_STAT_MAX
};

// Helper functions
static __always_inline int ip_match(__u32 ip, __u32 target, __u32 mask) {
    return (ip & mask) == (target & mask);
}

static __always_inline __u8 get_protocol(struct iphdr *iph) {
    return iph->protocol;
}

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

// Main TC ingress program
SEC("tc")
int tc_ingress_prog(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Update total packet counter
    __u32 key = TC_STAT_PACKETS_TOTAL;
    __u64 *total = bpf_map_lookup_elem(&tc_stats, &key);
    if (total) {
        __sync_fetch_and_add(total, 1);
    }
    
    // Update total bytes counter
    key = TC_STAT_BYTES_TOTAL;
    __u64 *bytes = bpf_map_lookup_elem(&tc_stats, &key);
    if (bytes) {
        __sync_fetch_and_add(bytes, skb->len);
    }
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }
    
    // Only handle IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    // Parse IP header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return TC_ACT_SHOT;
    }
    
    __u32 src_ip = bpf_ntohl(iph->saddr);
    __u32 dst_ip = bpf_ntohl(iph->daddr);
    __u8 protocol = get_protocol(iph);
    __u16 src_port = 0, dst_port = 0;
    
    get_ports(iph, data_end, &src_port, &dst_port);
    
    // Apply filters
    struct filter *filter;
    __u32 filter_key = 0;
    
    // Simple filter lookup
    filter = bpf_map_lookup_elem(&filters, &filter_key);
    if (filter) {
        if (ip_match(src_ip, filter->src_ip, filter->src_mask) &&
            ip_match(dst_ip, filter->dst_ip, filter->dst_mask) &&
            (filter->protocol == 0 || filter->protocol == protocol) &&
            (filter->src_port == 0 || filter->src_port == src_port) &&
            (filter->dst_port == 0 || filter->dst_port == dst_port)) {
            
            // Get traffic class
            struct traffic_class *tc;
            __u32 class_key = filter->class_id;
            tc = bpf_map_lookup_elem(&traffic_classes, &class_key);
            
            if (tc) {
                if (tc->action == 1) { // DROP
                    key = TC_STAT_PACKETS_DROPPED;
                    __u64 *dropped = bpf_map_lookup_elem(&tc_stats, &key);
                    if (dropped) {
                        __sync_fetch_and_add(dropped, 1);
                    }
                    return TC_ACT_SHOT;
                } else if (tc->action == 2) { // MARK
                    bpf_skb_set_tc_index(skb, tc->mark_value);
                    key = TC_STAT_PACKETS_MARKED;
                    __u64 *marked = bpf_map_lookup_elem(&tc_stats, &key);
                    if (marked) {
                        __sync_fetch_and_add(marked, 1);
                    }
                }
            }
        }
    }
    
    // Default: PASS
    key = TC_STAT_PACKETS_PASSED;
    __u64 *passed = bpf_map_lookup_elem(&tc_stats, &key);
    if (passed) {
        __sync_fetch_and_add(passed, 1);
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
