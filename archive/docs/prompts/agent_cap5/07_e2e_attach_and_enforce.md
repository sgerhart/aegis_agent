Goal: E2E validation on a dev host

- Build: `make -C bpf && make build`
- Start agent (compose or systemd)
- Post MapSnapshot via orchestrator; verify:
  - Agent logs 'APPLY snapshot'
  - Maps contain entries
  - TC/cgroup programs attached
  - Traffic to non-allowed dests is denied (observe counters/logs)
