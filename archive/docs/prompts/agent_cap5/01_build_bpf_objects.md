Goal: Build CO-RE .o files for seg_egress_cgroup and seg_ingress_tc

- Ensure clang/llvm available on dev host (>=14 preferred).
- Open bpf/Makefile and run: `make -C bpf`
- Commit the two .o artifacts or configure CI to build on release tags.
- Verify: `file bpf/*.o` shows `BPF` ELF.
