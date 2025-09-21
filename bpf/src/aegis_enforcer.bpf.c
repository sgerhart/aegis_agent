#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// AEGIS eBPF Policy Enforcement Program
// Communicates with backend via shared BPF maps

// Policy enforcement map - populated by agent from backend instructions
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);     // IP address (network byte order)
    __type(value, __u8);    // Protocol to block (1=ICMP, 6=TCP, 17=UDP, 255=ALL)
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aegis_blocked_destinations SEC(".maps");

// Enforcement statistics - read by agent for telemetry to backend
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 20);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aegis_enforcement_stats SEC(".maps");

// Policy metadata - instructions from backend
struct policy_rule {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u8  protocol;
    __u8  action;      // 0=allow, 1=drop, 2=redirect
    __u16 priority;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct policy_rule);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aegis_policy_rules SEC(".maps");

// Statistics keys for telemetry
#define STAT_PACKETS_PROCESSED     0
#define STAT_PACKETS_BLOCKED       1
#define STAT_ICMP_BLOCKED          2
#define STAT_TCP_BLOCKED           3
#define STAT_UDP_BLOCKED           4
#define STAT_POLICY_VIOLATIONS     5
#define STAT_BACKEND_INSTRUCTIONS  6
#define STAT_TELEMETRY_EVENTS      7

static inline void update_stat(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&aegis_enforcement_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

static inline int check_policy_rules(__u32 src_ip, __u32 dest_ip, __u16 src_port, __u16 dest_port, __u8 protocol) {
    // Check detailed policy rules from backend
    for (__u32 i = 0; i < 1024; i++) {
        struct policy_rule *rule = bpf_map_lookup_elem(&aegis_policy_rules, &i);
        if (!rule || rule->action == 0) // No rule or allow
            continue;
            
        // Match rule conditions
        if ((rule->src_ip == 0 || rule->src_ip == src_ip) &&
            (rule->dest_ip == 0 || rule->dest_ip == dest_ip) &&
            (rule->src_port == 0 || rule->src_port == src_port) &&
            (rule->dest_port == 0 || rule->dest_port == dest_port) &&
            (rule->protocol == 0 || rule->protocol == protocol)) {
            
            if (rule->action == 1) { // Drop
                update_stat(STAT_POLICY_VIOLATIONS);
                return 1; // Block
            }
        }
    }
    return 0; // Allow
}

SEC("classifier")
int aegis_enforce(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    update_stat(STAT_PACKETS_PROCESSED);
    
    // Only process IPv4 for now
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dest_ip = bpf_ntohl(ip->daddr);
    __u8 protocol = ip->protocol;
    __u16 src_port = 0, dest_port = 0;
    
    // Extract port information
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) <= data_end) {
            src_port = bpf_ntohs(tcp->source);
            dest_port = bpf_ntohs(tcp->dest);
        }
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) <= data_end) {
            src_port = bpf_ntohs(udp->source);
            dest_port = bpf_ntohs(udp->dest);
        }
    }
    
    // Check simple blocked destinations first (legacy support)
    __u8 *blocked_proto = bpf_map_lookup_elem(&aegis_blocked_destinations, &dest_ip);
    if (blocked_proto && (*blocked_proto == protocol || *blocked_proto == 255)) {
        update_stat(STAT_PACKETS_BLOCKED);
        
        switch (protocol) {
            case IPPROTO_ICMP:
                update_stat(STAT_ICMP_BLOCKED);
                break;
            case IPPROTO_TCP:
                update_stat(STAT_TCP_BLOCKED);
                break;
            case IPPROTO_UDP:
                update_stat(STAT_UDP_BLOCKED);
                break;
        }
        
        bpf_printk("AEGIS: Simple rule blocked %d to %pI4", protocol, &dest_ip);
        return TC_ACT_SHOT;
    }
    
    // Check detailed policy rules from backend
    if (check_policy_rules(src_ip, dest_ip, src_port, dest_port, protocol)) {
        update_stat(STAT_PACKETS_BLOCKED);
        bpf_printk("AEGIS: Policy rule blocked %pI4:%d -> %pI4:%d", 
                   &src_ip, src_port, &dest_ip, dest_port);
        return TC_ACT_SHOT;
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
