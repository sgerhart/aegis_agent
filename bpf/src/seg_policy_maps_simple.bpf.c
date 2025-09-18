// SPDX-License-Identifier: GPL-2.0
// AegisFlux Segmentation Policy Maps (Simplified)
// Defines pinned maps for policy management and enforcement

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

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
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 512);
    __type(key, struct allow_cidr);
    __type(value, __u8);
    __uint(pinning, PIN_GLOBAL_NS);
} allow_lpm4 SEC(".maps");

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

// Helper function to get current timestamp
static __always_inline __u64 get_timestamp() {
    return bpf_ktime_get_ns();
}

// Dummy program that can be attached to verify maps work
SEC("cgroup/connect4")
int policy_enforcer_connect4(struct bpf_sock_addr *ctx)
{
    // This is a dummy program that just returns ALLOW
    // In a real implementation, this would check policies
    return 1; // ALLOW
}

SEC("cgroup/connect6")
int policy_enforcer_connect6(struct bpf_sock_addr *ctx)
{
    // This is a dummy program that just returns ALLOW
    // In a real implementation, this would check policies
    return 1; // ALLOW
}

char _license[] SEC("license") = "GPL";
