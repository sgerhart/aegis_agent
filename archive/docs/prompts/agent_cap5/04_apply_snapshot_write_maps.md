Goal: Wire ApplySnapshot to WriteEdges/WriteAllowCIDRs

- internal/seg/subscriber.go already calls ApplySnapshot
- internal/policy/encoder.go covers encoding; update as needed
- Test: publish a sample MapSnapshot to NATS and confirm map entries appear
