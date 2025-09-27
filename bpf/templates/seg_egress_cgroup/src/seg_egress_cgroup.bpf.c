#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
SEC("cgroup/connect4") int seg_connect4(struct bpf_sock_addr *ctx){ return 0; }
