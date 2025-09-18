Goal: Enforce signature verification on bundles

- Use verify.VerifyBundle(pubKeyPEM, data, b64sig) prior to any load
- Add env var AGENT_VERIFY=strict|permissive (strict recommended)
- Negative test: altered bytes must fail and be reported on agent.telemetry
