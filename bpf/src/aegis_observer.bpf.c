#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// AEGIS eBPF Observability Program
// Collects telemetry data for backend reporting

// Network flow tracking for telemetry
struct flow_key {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u8  protocol;
    __u8  direction; // 0=ingress, 1=egress
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
    __u32 flags;     // TCP flags for connection tracking
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aegis_network_flows SEC(".maps");

// Top talkers by bytes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // IP address
    __type(value, __u64);  // Byte count
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aegis_top_talkers SEC(".maps");

// Protocol distribution for telemetry
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);  // One per protocol number
    __type(key, __u32);        // Protocol number
    __type(value, __u64);      // Packet count
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aegis_protocol_stats SEC(".maps");

// Security events for backend alerting
struct security_event {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u8  protocol;
    __u8  event_type; // 1=suspicious, 2=violation, 3=anomaly
    __u16 severity;   // 1-10
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aegis_security_events SEC(".maps");

// Global observability statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 30);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aegis_observability_stats SEC(".maps");

// Observability statistics keys
#define OBS_TOTAL_PACKETS       0
#define OBS_TOTAL_BYTES         1
#define OBS_UNIQUE_FLOWS        2
#define OBS_TCP_CONNECTIONS     3
#define OBS_UDP_SESSIONS        4
#define OBS_ICMP_PACKETS        5
#define OBS_SUSPICIOUS_ACTIVITY 6
#define OBS_BACKEND_REPORTS     7

static inline void update_obs_stat(__u32 key, __u64 value) {
    __u64 *count = bpf_map_lookup_elem(&aegis_observability_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, value);
    }
}

static inline void report_security_event(__u32 src_ip, __u32 dest_ip, 
                                        __u16 src_port, __u16 dest_port,
                                        __u8 protocol, __u8 event_type, __u16 severity) {
    struct security_event *event = bpf_ringbuf_reserve(&aegis_security_events, 
                                                       sizeof(struct security_event), 0);
    if (!event)
        return;
    
    event->timestamp = bpf_ktime_get_ns();
    event->src_ip = src_ip;
    event->dest_ip = dest_ip;
    event->src_port = src_port;
    event->dest_port = dest_port;
    event->protocol = protocol;
    event->event_type = event_type;
    event->severity = severity;
    
    bpf_ringbuf_submit(event, 0);
    update_obs_stat(OBS_SUSPICIOUS_ACTIVITY, 1);
}

SEC("classifier")
int aegis_observe(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    __u64 now = bpf_ktime_get_ns();
    __u32 packet_size = skb->len;
    
    update_obs_stat(OBS_TOTAL_PACKETS, 1);
    update_obs_stat(OBS_TOTAL_BYTES, packet_size);
    
    // Track protocol distribution
    __u32 protocol_key = ip->protocol;
    __u64 *proto_count = bpf_map_lookup_elem(&aegis_protocol_stats, &protocol_key);
    if (proto_count) {
        __sync_fetch_and_add(proto_count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&aegis_protocol_stats, &protocol_key, &initial, BPF_ANY);
    }
    
    // Track network flows
    struct flow_key key = {
        .src_ip = bpf_ntohl(ip->saddr),
        .dest_ip = bpf_ntohl(ip->daddr),
        .protocol = ip->protocol,
        .direction = (skb->ingress_ifindex != 0) ? 0 : 1, // ingress/egress
        .src_port = 0,
        .dest_port = 0
    };
    
    __u32 tcp_flags = 0;
    
    // Extract port information and TCP flags
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) <= data_end) {
            key.src_port = bpf_ntohs(tcp->source);
            key.dest_port = bpf_ntohs(tcp->dest);
            tcp_flags = (tcp->fin << 0) | (tcp->syn << 1) | (tcp->rst << 2) |
                       (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
        }
        update_obs_stat(OBS_TCP_CONNECTIONS, 1);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) <= data_end) {
            key.src_port = bpf_ntohs(udp->source);
            key.dest_port = bpf_ntohs(udp->dest);
        }
        update_obs_stat(OBS_UDP_SESSIONS, 1);
    } else if (ip->protocol == IPPROTO_ICMP) {
        update_obs_stat(OBS_ICMP_PACKETS, 1);
    }
    
    // Update flow statistics
    struct flow_stats *flow = bpf_map_lookup_elem(&aegis_network_flows, &key);
    if (flow) {
        __sync_fetch_and_add(&flow->packets, 1);
        __sync_fetch_and_add(&flow->bytes, packet_size);
        flow->last_seen = now;
        flow->flags |= tcp_flags; // Accumulate TCP flags
    } else {
        struct flow_stats new_flow = {
            .packets = 1,
            .bytes = packet_size,
            .first_seen = now,
            .last_seen = now,
            .flags = tcp_flags
        };
        bpf_map_update_elem(&aegis_network_flows, &key, &new_flow, BPF_ANY);
        update_obs_stat(OBS_UNIQUE_FLOWS, 1);
    }
    
    // Update top talkers
    __u64 *bytes = bpf_map_lookup_elem(&aegis_top_talkers, &key.dest_ip);
    if (bytes) {
        __sync_fetch_and_add(bytes, packet_size);
    } else {
        __u64 initial = packet_size;
        bpf_map_update_elem(&aegis_top_talkers, &key.dest_ip, &initial, BPF_ANY);
    }
    
    // Detect suspicious patterns
    if (ip->protocol == IPPROTO_TCP && tcp_flags == 0x02) { // SYN only
        // Port scanning detection (simplified)
        if (key.dest_port > 1024 && key.dest_port < 65535) {
            report_security_event(key.src_ip, key.dest_ip, key.src_port, 
                                 key.dest_port, ip->protocol, 1, 3); // Suspicious, severity 3
        }
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
