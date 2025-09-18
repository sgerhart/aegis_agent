#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
SEC("classifier") int seg_ingress_cls(struct __sk_buff *skb){ return TC_ACT_OK; }
