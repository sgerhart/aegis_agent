Goal: Create pinned maps and seed entries

- After loading objects, ensure pinned maps exist under /sys/fs/bpf/aegis
- Use bpftool or cilium/ebpf to create pins for policy_edges and allow_lpm4
- Write a tiny seeding command to add one edge and one allow_cidr
- Verify with: `bpftool map dump pinned /sys/fs/bpf/aegis/policy_edges`
