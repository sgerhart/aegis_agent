// SPDX-License-Identifier: GPL-2.0
// AegisFlux Segmentation Egress Cgroup Program
// Monitors and controls outbound connections at the cgroup level

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Configuration
#define MAX_POLICIES 256
#define MAX_PROCESSES 1024
#define MAX_PORTS 1024

// Policy structure for egress control
struct egress_policy {
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
};

// Process information structure
struct process_info {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    __u8 namespace_id;
    __u64 last_seen;
};

// Statistics structure
struct egress_stats {
    __u64 total_connections;
    __u64 allowed_connections;
    __u64 blocked_connections;
    __u64 logged_connections;
    __u64 policy_hits[MAX_POLICIES];
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_POLICIES);
    __type(key, __u32);
    __type(value, struct egress_policy);
} egress_policies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);
    __type(value, struct process_info);
} process_info_map SEC(".maps");

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
    __type(value, struct egress_stats);
} egress_stats_map SEC(".maps");

// Helper function to get process information
static __always_inline struct process_info* get_process_info(__u32 pid) {
    return bpf_map_lookup_elem(&process_info_map, &pid);
}

// Helper function to update process information
static __always_inline void update_process_info(__u32 pid, __u32 uid, __u32 gid) {
    struct process_info info = {
        .pid = pid,
        .uid = uid,
        .gid = gid,
        .last_seen = bpf_ktime_get_ns(),
    };
    
    bpf_get_current_comm(info.comm, sizeof(info.comm));
    bpf_map_update_elem(&process_info_map, &pid, &info, BPF_ANY);
}

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
static __always_inline void update_stats(__u32 stat_type, __u32 policy_id) {
    __u32 key = 0;
    struct egress_stats *stats = bpf_map_lookup_elem(&egress_stats_map, &key);
    if (!stats) return;
    
    __sync_fetch_and_add(&stats->total_connections, 1);
    
    switch (stat_type) {
        case 0: // ALLOW
            __sync_fetch_and_add(&stats->allowed_connections, 1);
            break;
        case 1: // BLOCK
            __sync_fetch_and_add(&stats->blocked_connections, 1);
            break;
        case 2: // LOG
            __sync_fetch_and_add(&stats->logged_connections, 1);
            break;
    }
    
    if (policy_id < MAX_POLICIES) {
        __sync_fetch_and_add(&stats->policy_hits[policy_id], 1);
    }
}

// Main cgroup connect4 program
SEC("cgroup/connect4")
int seg_connect4(struct bpf_sock_addr *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 gid = bpf_get_current_uid_gid() >> 32;
    
    // Update process information
    update_process_info(pid, uid, gid);
    
    // Get connection details
    __u32 src_ip = ctx->user_ip4;
    __u32 dst_ip = ctx->user_ip4; // This would be the destination IP in real implementation
    __u16 src_port = ctx->user_port;
    __u16 dst_port = 0; // This would be the destination port in real implementation
    
    // Update total connections
    update_stats(0, 0); // Use 0 for total count
    
    // Check policies
    struct egress_policy *policy;
    __u32 policy_key = 0;
    
    // Simple policy lookup (in real implementation, use more sophisticated matching)
    policy = bpf_map_lookup_elem(&egress_policies, &policy_key);
    if (policy) {
        // Check if connection matches policy
        if (ip_match(src_ip, policy->src_ip, policy->src_mask) &&
            ip_match(dst_ip, policy->dst_ip, policy->dst_mask) &&
            port_match(src_port, policy->src_port) &&
            port_match(dst_port, policy->dst_port) &&
            protocol_match(IPPROTO_TCP, policy->protocol) &&
            (policy->process_uid == 0 || policy->process_uid == uid) &&
            (policy->process_gid == 0 || policy->process_gid == gid)) {
            
            if (policy->action == 1) { // ALLOW
                update_stats(0, policy_key);
                return 1; // Allow connection
            } else if (policy->action == 2) { // LOG
                update_stats(2, policy_key);
                // Continue processing after logging
            }
        }
    }
    
    // Check port-based rules
    __u8 *port_allowed = bpf_map_lookup_elem(&allowed_ports, &dst_port);
    if (port_allowed && *port_allowed) {
        update_stats(0, 0);
        return 1; // Allow connection
    }
    
    // Default action: BLOCK
    update_stats(1, 0);
    return 0; // Block connection
}

// Main cgroup connect6 program
SEC("cgroup/connect6")
int seg_connect6(struct bpf_sock_addr *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 gid = bpf_get_current_uid_gid() >> 32;
    
    // Update process information
    update_process_info(pid, uid, gid);
    
    // Get connection details (IPv6)
    __u32 src_ip[4];
    __u32 dst_ip[4];
    __u16 src_port = ctx->user_port;
    __u16 dst_port = 0; // This would be the destination port in real implementation
    
    // Extract IPv6 addresses (simplified - in real implementation, extract from ctx->user_ip6)
    src_ip[0] = 0; src_ip[1] = 0; src_ip[2] = 0; src_ip[3] = 0;
    dst_ip[0] = 0; dst_ip[1] = 0; dst_ip[2] = 0; dst_ip[3] = 0;
    
    // Update total connections
    update_stats(0, 0);
    
    // Check policies (simplified for IPv6)
    struct egress_policy *policy;
    __u32 policy_key = 0;
    
    policy = bpf_map_lookup_elem(&egress_policies, &policy_key);
    if (policy) {
        // Check if connection matches policy
        if (port_match(src_port, policy->src_port) &&
            port_match(dst_port, policy->dst_port) &&
            protocol_match(IPPROTO_TCP, policy->protocol) &&
            (policy->process_uid == 0 || policy->process_uid == uid) &&
            (policy->process_gid == 0 || policy->process_gid == gid)) {
            
            if (policy->action == 1) { // ALLOW
                update_stats(0, policy_key);
                return 1; // Allow connection
            } else if (policy->action == 2) { // LOG
                update_stats(2, policy_key);
                // Continue processing after logging
            }
        }
    }
    
    // Check port-based rules
    __u8 *port_allowed = bpf_map_lookup_elem(&allowed_ports, &dst_port);
    if (port_allowed && *port_allowed) {
        update_stats(0, 0);
        return 1; // Allow connection
    }
    
    // Default action: BLOCK
    update_stats(1, 0);
    return 0; // Block connection
}

// Helper program for process monitoring
SEC("kprobe/sys_connect")
int trace_connect(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 gid = bpf_get_current_uid_gid() >> 32;
    
    // Update process information
    update_process_info(pid, uid, gid);
    
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
