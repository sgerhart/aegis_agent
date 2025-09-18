#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct allow_val {
    __u16 dport;
    __u8  proto;
    __u8  _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, struct allow_val);
    __uint(max_entries, 8192);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} allow_lpm4 SEC(".maps");

SEC("classifier")
int seg_ingress_cls(struct __sk_buff *skb) {
    return TC_ACT_OK; // stub: allow all
}
