# AegisFlux Agent Deployment Guide

This guide covers deploying the AegisFlux eBPF agent using systemd or Docker containers.

## Prerequisites

### System Requirements
- Linux kernel 4.15+ with eBPF support
- Root privileges or appropriate capabilities
- Go 1.21+ (for building from source)

### Required Capabilities
- `CAP_BPF` - for eBPF program loading
- `CAP_NET_ADMIN` - for network-related eBPF programs
- `CAP_SYS_ADMIN` - for system-wide eBPF operations

## Systemd Deployment

### 1. Build the Agent
```bash
cd agents/local-agent-go
go build -o aegisflux-agent ./cmd/agent
```

### 2. Install the Agent
```bash
# Create directories
sudo mkdir -p /opt/aegisflux/bin /opt/aegisflux/bundles /var/log/aegisflux

# Copy binary
sudo cp aegisflux-agent /opt/aegisflux/bin/
sudo chmod +x /opt/aegisflux/bin/aegisflux-agent

# Copy systemd unit
sudo cp deploy/systemd/aegisflux-agent.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload
```

### 3. Configure Environment
Edit `/etc/systemd/system/aegisflux-agent.service` to set your environment variables:

```ini
Environment=AGENT_REGISTRY_URL=http://your-registry:8090
Environment=NATS_URL=nats://your-nats:4222
Environment=AGENT_HOST_ID=your-host-id
Environment=VAULT_URL=http://your-vault:8200
Environment=VAULT_TOKEN=your-vault-token
Environment=DEV_PUBLIC_KEY_PATH=/path/to/public-key.pem
```

### 4. Start the Service
```bash
sudo systemctl enable aegisflux-agent
sudo systemctl start aegisflux-agent
sudo systemctl status aegisflux-agent
```

### 5. View Logs
```bash
sudo journalctl -u aegisflux-agent -f
```

## Docker Deployment

### 1. Using Docker Compose (Recommended)
```bash
cd agents/local-agent-go

# Set environment variables
export HOST_ID="your-host-id"
export VAULT_URL="http://your-vault:8200"
export VAULT_TOKEN="your-vault-token"

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f aegisflux-agent
```

### 2. Using Docker Run
```bash
# Build the image
docker build -t aegisflux-agent .

# Run the container
docker run -d \
  --name aegisflux-agent \
  --privileged \
  --cap-add=BPF \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_ADMIN \
  -p 7070:7070 \
  -e AGENT_REGISTRY_URL=http://your-registry:8090 \
  -e NATS_URL=nats://your-nats:4222 \
  -e AGENT_HOST_ID=your-host-id \
  -v ./bundles:/opt/aegisflux/bundles \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  aegisflux-agent
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_REGISTRY_URL` | `http://localhost:8090` | Registry server URL |
| `NATS_URL` | `nats://localhost:4222` | NATS server URL |
| `AGENT_HTTP_ADDR` | `:7070` | HTTP server address |
| `AGENT_POLL_INTERVAL` | `10s` | Registry polling interval |
| `AGENT_BUNDLES_DIR` | `./bundles` | Directory for downloaded bundles |
| `AGENT_HOST_ID` | `host-unknown` | Unique host identifier |
| `VAULT_URL` | `` | Vault server URL for signature verification |
| `VAULT_TOKEN` | `` | Vault authentication token |
| `DEV_PUBLIC_KEY_PATH` | `` | Path to development public key |

### Health Checks

The agent exposes health check endpoints:

- `GET /healthz` - Basic health check
- `GET /status` - Detailed status including loaded artifacts

Example:
```bash
curl http://localhost:7070/healthz
curl http://localhost:7070/status
```

## Security Considerations

### Systemd Security
The systemd unit file includes several security hardening features:
- `NoNewPrivileges=true` - Prevents privilege escalation
- `ProtectSystem=strict` - Protects system directories
- `MemoryDenyWriteExecute=true` - Prevents code injection
- `RestrictNamespaces=true` - Restricts namespace creation

### Docker Security
- Uses non-root user when possible
- Minimal Alpine Linux base image
- Read-only filesystem where possible
- Capability restrictions

### eBPF Security
- Signature verification for all loaded programs
- CPU usage monitoring with automatic rollback
- Drift detection and TTL management

## Monitoring

### Metrics
The agent emits telemetry events to NATS:
- `loaded` - Artifact successfully loaded
- `unloaded` - Artifact unloaded
- `error` - Error occurred
- `rolled_back` - Artifact rolled back due to issues

### Logs
- Systemd: `journalctl -u aegisflux-agent`
- Docker: `docker logs aegisflux-agent`

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure the agent has required capabilities
   - Check if eBPF is enabled in the kernel

2. **eBPF Program Loading Fails**
   - Verify kernel version (4.15+)
   - Check if BTF is available
   - Ensure proper capabilities

3. **Registry Connection Issues**
   - Verify registry URL and connectivity
   - Check firewall rules

4. **NATS Connection Issues**
   - Verify NATS URL and connectivity
   - Check authentication if required

### Debug Mode
Run with debug logging:
```bash
export RUST_LOG=debug  # If using Rust components
./aegisflux-agent
```

## Production Deployment

### High Availability
- Deploy multiple agent instances
- Use load balancer for registry/NATS
- Implement proper monitoring and alerting

### Scaling
- Each agent can handle multiple artifacts
- Monitor CPU and memory usage
- Implement proper resource limits

### Backup and Recovery
- Backup configuration files
- Implement artifact versioning
- Test rollback procedures regularly
