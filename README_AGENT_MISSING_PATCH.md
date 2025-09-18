# Aegis Agent — Cap 5 Missing Pieces Patch
Generated: 2025-09-18T17:08:54.577846Z

This package adds everything needed to finish Cap 5.A/B/C for the agent:
- CO-RE eBPF templates + Makefile
- Policy encoder that writes pinned maps
- NATS subscriber that applies MapSnapshots
- Loader skeletons for cgroup connect4 and TC ingress
- RSA signature verification helper
- Cursor prompts to complete the implementation

## Drop-in
Unzip at the root of your agent repo. Merge or move files to match your structure.

## Build BPF
```bash
make -C bpf
```

## Next in Cursor
- `prompts/agent_cap5/01_build_bpf_objects.md`
- `prompts/agent_cap5/02_attach_connect_and_tc.md`
- `prompts/agent_cap5/03_pin_and_seed_maps.md`
- `prompts/agent_cap5/04_apply_snapshot_write_maps.md`
- `prompts/agent_cap5/05_signature_verification.md`
- `prompts/agent_cap5/06_cpu_guard_and_rollback.md`
- `prompts/agent_cap5/07_e2e_attach_and_enforce.md`
