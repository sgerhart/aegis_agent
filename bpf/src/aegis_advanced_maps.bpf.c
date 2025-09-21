// eBPF program for advanced Aegis maps
// This program defines the specialized maps for complex network policies

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Network Policy Map
// Key: Policy ID (uint32)
// Value: Network Policy struct
struct network_policy {
    __u32 policy_id;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 src_mask;
    __u32 dst_mask;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 action;        // 0=BLOCK, 1=ALLOW, 2=LOG, 3=RATE_LIMIT
    __u8 priority;
    __u32 rate_limit;   // packets per second
    char process_name[16];
    __u32 user_id;
    __u32 group_id;
    __u32 namespace_id;
    __u64 timestamp;
    __u32 ttl;
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct network_policy);
} network_policies_map SEC(".maps");

// Service Dependencies Map
// Key: Composite key (service_id << 32 | depends_on_id)
// Value: Service Dependency struct
struct service_dependency {
    __u32 service_id;
    char service_name[32];
    __u32 depends_on_id;
    char depends_on_name[32];
    __u16 port;
    __u8 protocol;
    __u8 health;        // 0=unknown, 1=healthy, 2=unhealthy, 3=degraded
    __u64 last_check;
    __u32 check_interval;
    __u32 timeout;
    __u8 retries;
    __u8 weight;
    __u8 padding[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5000);
    __type(key, __u64);
    __type(value, struct service_dependency);
} service_deps_map SEC(".maps");

// Process Connections Map
// Key: Composite key (process_id << 32 | connection_hash)
// Value: Process Connection struct
struct process_connection {
    __u32 process_id;
    char process_name[32];
    __u32 user_id;
    __u32 group_id;
    __u32 namespace_id;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 state;         // 0=unknown, 1=established, 2=time_wait, 3=close_wait
    __u64 bytes_in;
    __u64 bytes_out;
    __u64 packets_in;
    __u64 packets_out;
    __u64 start_time;
    __u64 last_activity;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50000);
    __type(key, __u64);
    __type(value, struct process_connection);
} process_connections_map SEC(".maps");

// Flow Statistics Map
// Key: Composite key (src_ip << 32 | dst_ip)
// Value: Flow Stats struct
struct flow_stats {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 padding[1];
    __u64 bytes_total;
    __u64 packets_total;
    __u32 duration;
    __u64 last_seen;
    __u32 flow_count;
    __u8 padding2[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u64);
    __type(value, struct flow_stats);
} flow_stats_map SEC(".maps");

// Policy Rules Map
// Key: Rule ID (uint32)
// Value: Policy Rule struct
struct policy_rule {
    __u32 rule_id;
    __u32 policy_id;
    __u8 rule_type;     // 0=network, 1=process, 2=file, 3=syscall
    __u8 action;        // 0=BLOCK, 1=ALLOW, 2=LOG, 3=RATE_LIMIT
    __u8 priority;
    __u8 enabled;
    __u8 condition_type; // 0=simple, 1=complex, 2=regex, 3=custom
    __u8 padding[3];
    char match_data[64];
    char action_data[32];
    __u64 timestamp;
    __u32 ttl;
    __u32 hit_count;
    __u64 last_hit;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20000);
    __type(key, __u32);
    __type(value, struct policy_rule);
} policy_rules_map SEC(".maps");

// Helper function to create composite key
static __always_inline __u64 create_composite_key(__u32 high, __u32 low) {
    return ((__u64)high << 32) | (__u64)low;
}

// Helper function to hash connection
static __always_inline __u32 hash_connection(__u32 src_ip, __u32 dst_ip, 
                                           __u16 src_port, __u16 dst_port, 
                                           __u8 protocol) {
    return src_ip ^ dst_ip ^ src_port ^ dst_port ^ protocol;
}

// Helper function to check if IP matches network
static __always_inline int ip_matches_network(__u32 ip, __u32 network, __u32 mask) {
    return (ip & mask) == (network & mask);
}

// Helper function to get current timestamp
static __always_inline __u64 get_timestamp() {
    return bpf_ktime_get_ns();
}

// Policy enforcement function
static __always_inline int enforce_network_policy(__u32 src_ip, __u32 dst_ip, 
                                                 __u16 src_port, __u16 dst_port, 
                                                 __u8 protocol) {
    struct network_policy *policy;
    __u32 policy_key = 1; // Start with policy ID 1
    
    // Look up network policies
    policy = bpf_map_lookup_elem(&network_policies_map, &policy_key);
    if (!policy) {
        return 1; // Allow if no policy found (default allow)
    }
    
    // Check if this packet matches the policy
    if (ip_matches_network(src_ip, policy->src_ip, policy->src_mask) &&
        ip_matches_network(dst_ip, policy->dst_ip, policy->dst_mask) &&
        (policy->src_port == 0 || src_port == policy->src_port) &&
        (policy->dst_port == 0 || dst_port == policy->dst_port) &&
        (policy->protocol == 0 || protocol == policy->protocol)) {
        
        // Update hit count and last hit time
        policy->hit_count++;
        policy->last_hit = get_timestamp();
        
        // Return action
        return policy->action;
    }
    
    return 1; // Default allow
}

// Flow statistics update function
static __always_inline void update_flow_stats(__u32 src_ip, __u32 dst_ip, 
                                             __u16 src_port, __u16 dst_port, 
                                             __u8 protocol, __u32 packet_size) {
    __u64 key = create_composite_key(src_ip, dst_ip);
    struct flow_stats *stats;
    
    stats = bpf_map_lookup_elem(&flow_stats_map, &key);
    if (!stats) {
        // Create new flow stats entry
        struct flow_stats new_stats = {};
        new_stats.src_ip = src_ip;
        new_stats.dst_ip = dst_ip;
        new_stats.src_port = src_port;
        new_stats.dst_port = dst_port;
        new_stats.protocol = protocol;
        new_stats.bytes_total = packet_size;
        new_stats.packets_total = 1;
        new_stats.duration = 0;
        new_stats.last_seen = get_timestamp();
        new_stats.flow_count = 1;
        
        bpf_map_update_elem(&flow_stats_map, &key, &new_stats, BPF_ANY);
    } else {
        // Update existing stats
        stats->bytes_total += packet_size;
        stats->packets_total++;
        stats->last_seen = get_timestamp();
        stats->flow_count++;
        
        bpf_map_update_elem(&flow_stats_map, &key, stats, BPF_ANY);
    }
}

// Process connection tracking function
static __always_inline void track_process_connection(__u32 process_id, 
                                                    char *process_name,
                                                    __u32 src_ip, __u32 dst_ip, 
                                                    __u16 src_port, __u16 dst_port, 
                                                    __u8 protocol, __u32 packet_size) {
    __u32 conn_hash = hash_connection(src_ip, dst_ip, src_port, dst_port, protocol);
    __u64 key = create_composite_key(process_id, conn_hash);
    struct process_connection *conn;
    
    conn = bpf_map_lookup_elem(&process_connections_map, &key);
    if (!conn) {
        // Create new process connection entry
        struct process_connection new_conn = {};
        new_conn.process_id = process_id;
        bpf_probe_read_str(new_conn.process_name, sizeof(new_conn.process_name), process_name);
        new_conn.src_ip = src_ip;
        new_conn.dst_ip = dst_ip;
        new_conn.src_port = src_port;
        new_conn.dst_port = dst_port;
        new_conn.protocol = protocol;
        new_conn.state = 1; // Established
        new_conn.bytes_in = packet_size;
        new_conn.packets_in = 1;
        new_conn.start_time = get_timestamp();
        new_conn.last_activity = get_timestamp();
        
        bpf_map_update_elem(&process_connections_map, &key, &new_conn, BPF_ANY);
    } else {
        // Update existing connection
        conn->bytes_in += packet_size;
        conn->packets_in++;
        conn->last_activity = get_timestamp();
        
        bpf_map_update_elem(&process_connections_map, &key, conn, BPF_ANY);
    }
}

// Service health check function
static __always_inline int check_service_health(__u32 service_id) {
    struct service_dependency *dep;
    __u64 key = create_composite_key(service_id, 0); // Look for first dependency
    
    dep = bpf_map_lookup_elem(&service_deps_map, &key);
    if (!dep) {
        return 1; // Healthy if no dependencies
    }
    
    // Check if service dependencies are healthy
    __u64 current_time = get_timestamp();
    if (current_time - dep->last_check > dep->check_interval * 1000000000ULL) {
        // Time to check dependency health
        // This is a simplified health check
        dep->health = 1; // Assume healthy
        dep->last_check = current_time;
        
        bpf_map_update_elem(&service_deps_map, &key, dep, BPF_ANY);
    }
    
    return dep->health;
}

// Main entry point for network packet processing
SEC("tc")
int aegis_advanced_packet_filter(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    
    // Basic packet validation
    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    ip = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }
    
    // Extract packet information
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u8 protocol = ip->protocol;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    // Extract port information based on protocol
    if (protocol == IPPROTO_TCP) {
        tcp = data + sizeof(struct ethhdr) + (ip->ihl << 2);
        if (data + sizeof(struct ethhdr) + (ip->ihl << 2) + sizeof(struct tcphdr) <= data_end) {
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (protocol == IPPROTO_UDP) {
        udp = data + sizeof(struct ethhdr) + (ip->ihl << 2);
        if (data + sizeof(struct ethhdr) + (ip->ihl << 2) + sizeof(struct udphdr) <= data_end) {
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
        }
    }
    
    // Enforce network policies
    int action = enforce_network_policy(src_ip, dst_ip, src_port, dst_port, protocol);
    
    // Update flow statistics
    update_flow_stats(src_ip, dst_ip, src_port, dst_port, protocol, skb->len);
    
    // Track process connections (simplified - would need process context)
    // track_process_connection(0, "unknown", src_ip, dst_ip, src_port, dst_port, protocol, skb->len);
    
    // Return action
    switch (action) {
        case 0: // BLOCK
            return TC_ACT_SHOT;
        case 1: // ALLOW
            return TC_ACT_OK;
        case 2: // LOG
            // Log packet (simplified)
            return TC_ACT_OK;
        case 3: // RATE_LIMIT
            // Rate limit (simplified)
            return TC_ACT_OK;
        default:
            return TC_ACT_OK;
    }
}

char _license[] SEC("license") = "GPL";
