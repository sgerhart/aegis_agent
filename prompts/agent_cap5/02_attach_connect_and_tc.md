Goal: Implement real attaches in internal/loader

- Use github.com/cilium/ebpf to load objects from bpf/*.o
- internal/loader/seg_egress.go:
  - Load program name `seg_connect4` and attach via link.AttachCgroup
- internal/loader/seg_ingress.go:
  - Ensure clsact qdisc via netlink, then attach classifier via link.AttachTC
- Success: attaching on a dev host returns valid links (no error).
