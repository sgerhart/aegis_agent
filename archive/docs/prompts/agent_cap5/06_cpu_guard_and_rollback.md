Goal: Tie CPU guard to detach/rollback

- On sustained CPU > threshold for active programs, detach and swap back to previous gen
- Emit telemetry: agent.telemetry {status: 'rollback', reason:'cpu_guard'}
- Add /status fields: cpu_pct, active_gen
