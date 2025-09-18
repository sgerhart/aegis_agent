# AegisFlux Local Agent (Go)

Lightweight host agent to fetch, verify, and load eBPF mitigation artifacts.

## Build
```bash
cd agents/local-agent-go
go mod tidy
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/aegisflux-agent ./cmd/agent
```

## Run
```bash
AGENT_REGISTRY_URL=http://localhost:8090 \
NATS_URL=nats://localhost:4222 \
sudo ./bin/aegisflux-agent
```
