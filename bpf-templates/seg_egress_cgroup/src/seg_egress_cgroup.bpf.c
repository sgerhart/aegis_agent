#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct key_v4 {
    __u32 service_id;
    __u8  proto;
    __u16 dport;
    __u32 daddr;
};

struct val_action {
    __u32 allow;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_v4);
    __type(value, struct val_action);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_edges SEC(".maps");

SEC("cgroup/connect4")
int seg_connect4(struct bpf_sock_addr *ctx) {
    struct key_v4 k = {0};
    k.proto = ctx->protocol;
    k.dport = ctx->user_port;
    k.daddr = ctx->user_ip4;
    struct val_action *v = bpf_map_lookup_elem(&policy_edges, &k);
    if (v && v->allow == 1) return 0;
    return -EPERM;
}
