// SPDX-License-Identifier: GPL-2.0
// Cgroup connect4 program for process isolation

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Configuration
#define MAX_POLICIES 256
#define MAX_PROCESSES 1024

// Process policy structure
struct process_policy {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 action; // 0=BLOCK, 1=ALLOW, 2=LOG
    __u8 priority;
};

// Process info structure
struct process_info {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    __u8 namespace_id;
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_POLICIES);
    __type(key, __u32);
    __type(value, struct process_policy);
} process_policies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);
    __type(value, struct process_info);
} process_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} connect_stats SEC(".maps");

// Statistics counters
enum {
    CONNECT_STAT_TOTAL,
    CONNECT_STAT_ALLOWED,
    CONNECT_STAT_BLOCKED,
    CONNECT_STAT_LOGGED,
    CONNECT_STAT_MAX
};

// Helper function to get process info
static __always_inline struct process_info* get_process_info(__u32 pid) {
    return bpf_map_lookup_elem(&process_info, &pid);
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

// Main cgroup connect4 program
SEC("cgroup/connect4")
int cgroup_connect4_prog(struct bpf_sock_addr *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 gid = bpf_get_current_uid_gid() >> 32;
    
    // Update total connection counter
    __u32 key = CONNECT_STAT_TOTAL;
    __u64 *total = bpf_map_lookup_elem(&connect_stats, &key);
    if (total) {
        __sync_fetch_and_add(total, 1);
    }
    
    // Get process info
    struct process_info *proc_info = get_process_info(pid);
    if (!proc_info) {
        // Create new process info entry
        struct process_info new_proc = {
            .pid = pid,
            .uid = uid,
            .gid = gid,
            .namespace_id = 0, // Would need to get from task_struct
        };
        
        // Get process name (simplified)
        bpf_get_current_comm(new_proc.comm, sizeof(new_proc.comm));
        
        // Store process info
        bpf_map_update_elem(&process_info, &pid, &new_proc, BPF_ANY);
        proc_info = &new_proc;
    }
    
    // Get connection details
    __u32 src_ip = ctx->user_ip4;
    __u32 dst_ip = ctx->user_ip4; // This would be the destination IP
    __u16 src_port = ctx->user_port;
    __u16 dst_port = 0; // This would be the destination port
    
    // Check policies
    struct process_policy *policy;
    __u32 policy_key = 0;
    
    // Simple policy lookup (in real implementation, use more sophisticated matching)
    policy = bpf_map_lookup_elem(&process_policies, &policy_key);
    if (policy) {
        // Check if connection matches policy
        if (ip_match(src_ip, policy->src_ip, 0xFFFFFFFF) &&
            ip_match(dst_ip, policy->dst_ip, 0xFFFFFFFF) &&
            port_match(src_port, policy->src_port) &&
            port_match(dst_port, policy->dst_port) &&
            protocol_match(IPPROTO_TCP, policy->protocol) &&
            (policy->pid == 0 || policy->pid == pid) &&
            (policy->uid == 0 || policy->uid == uid) &&
            (policy->gid == 0 || policy->gid == gid)) {
            
            if (policy->action == 1) { // ALLOW
                key = CONNECT_STAT_ALLOWED;
                __u64 *allowed = bpf_map_lookup_elem(&connect_stats, &key);
                if (allowed) {
                    __sync_fetch_and_add(allowed, 1);
                }
                return 1; // Allow connection
            } else if (policy->action == 2) { // LOG
                key = CONNECT_STAT_LOGGED;
                __u64 *logged = bpf_map_lookup_elem(&connect_stats, &key);
                if (logged) {
                    __sync_fetch_and_add(logged, 1);
                }
                // Continue processing after logging
            }
        }
    }
    
    // Default action: BLOCK
    key = CONNECT_STAT_BLOCKED;
    __u64 *blocked = bpf_map_lookup_elem(&connect_stats, &key);
    if (blocked) {
        __sync_fetch_and_add(blocked, 1);
    }
    
    return 0; // Block connection
}

char _license[] SEC("license") = "GPL";
