#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define TC action constants if not available
#ifndef TC_ACT_OK
#define TC_ACT_OK    0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT  2
#endif

// AEGIS Simple eBPF Enforcement Program
// Blocks specific IPs based on BPF map entries

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
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aegis_enforcement_stats SEC(".maps");

// Statistics keys for telemetry
#define STAT_PACKETS_PROCESSED 0
#define STAT_PACKETS_BLOCKED   1
#define STAT_ICMP_BLOCKED      2

static inline void update_stat(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&aegis_enforcement_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
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
    
    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    __u32 dest_ip = bpf_ntohl(ip->daddr);
    __u8 protocol = ip->protocol;
    
    // Check if this destination/protocol should be blocked
    __u8 *blocked_proto = bpf_map_lookup_elem(&aegis_blocked_destinations, &dest_ip);
    if (blocked_proto && (*blocked_proto == protocol || *blocked_proto == 255)) {
        update_stat(STAT_PACKETS_BLOCKED);
        
        if (protocol == 1) { // ICMP
            update_stat(STAT_ICMP_BLOCKED);
        }
        
        bpf_printk("AEGIS: Blocked protocol %d to IP %pI4", protocol, &dest_ip);
        return TC_ACT_SHOT;  // Drop packet
    }
    
    return TC_ACT_OK;  // Allow packet
}

char _license[] SEC("license") = "GPL";
