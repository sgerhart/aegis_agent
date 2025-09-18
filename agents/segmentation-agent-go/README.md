# 🛡️ AegisFlux Segmentation Agent

A high-performance eBPF-based segmentation agent for network and process isolation, built with Go and CO-RE (Compile Once - Run Everywhere) eBPF programs.

## 🚀 Features

- **Network Segmentation**: XDP and TC-based packet filtering and traffic control
- **Process Isolation**: Cgroup-based connection control and process sandboxing
- **Policy Engine**: Dynamic policy management with rule-based access control
- **CO-RE Build System**: Real clang/llvm + bpftool integration for portable eBPF programs
- **Observability**: Comprehensive metrics and event publishing via NATS
- **Capability Detection**: Automatic system capability probing and reporting

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Policy Engine │    │   eBPF Loader   │    │  CO-RE Builder  │
│                 │    │                 │    │                 │
│ • Rule Engine   │    │ • Program Mgmt  │    │ • clang/llvm    │
│ • Policy Store  │    │ • Map Updates   │    │ • bpftool       │
│ • Evaluation    │    │ • Attachments   │    │ • BTF Gen       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  eBPF Programs  │
                    │                 │
                    │ • XDP (Network) │
                    │ • TC (Traffic)  │
                    │ • Cgroup (Proc) │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Observability  │
                    │                 │
                    │ • Metrics       │
                    │ • Events        │
                    │ • NATS Pub      │
                    └─────────────────┘
```

## 📋 Prerequisites

- Linux kernel 5.4+ with eBPF support
- BTF (BPF Type Format) available
- Root privileges for eBPF operations
- clang/llvm for eBPF compilation
- bpftool for BTF operations
- NATS server for observability

## 🛠️ Installation

### Docker (Recommended)

```bash
# Build the image
docker build -t aegisflux/segmentation-agent .

# Run with required capabilities
docker run --privileged \
  --cap-add=BPF \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_ADMIN \
  -p 8080:8080 \
  -e NATS_URL=nats://host.docker.internal:4222 \
  aegisflux/segmentation-agent
```

### Systemd Service

```bash
# Install the service
sudo cp deploy/systemd/segmentation-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable segmentation-agent
sudo systemctl start segmentation-agent
```

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_HTTP_ADDR` | `:8080` | HTTP server address |
| `AGENT_POLL_INTERVAL` | `30s` | Policy polling interval |
| `AGENT_HOST_ID` | `segmentation-host` | Unique host identifier |
| `NATS_URL` | `nats://localhost:4222` | NATS server URL |
| `CLANG_PATH` | `clang` | Path to clang compiler |
| `BPFTOOL_PATH` | `bpftool` | Path to bpftool |
| `BTF_PATH` | `/sys/kernel/btf/vmlinux` | BTF file path |
| `BUILD_OUTPUT_DIR` | `./ebpf` | eBPF program output directory |

### Policy Configuration

Policies are defined in JSON format and can be managed via the policy engine:

```json
{
  "id": "network-policy-1",
  "name": "Web Server Access",
  "type": "network",
  "priority": 100,
  "enabled": true,
  "rules": [
    {
      "id": "allow-http",
      "action": "allow",
      "priority": 1,
      "conditions": [
        {"field": "protocol", "operator": "eq", "value": "tcp"},
        {"field": "dest_port", "operator": "eq", "value": 80}
      ]
    }
  ]
}
```

## 🧪 Testing

### Run E2E Tests

```bash
# Run as root (required for eBPF)
sudo go run test_e2e.go
```

### Test Individual Components

```bash
# Test capability detection
go run -tags test ./internal/capability

# Test policy engine
go run -tags test ./internal/policy

# Test eBPF loader
go run -tags test ./internal/loader
```

## 📊 Monitoring

### Health Endpoints

- `GET /healthz` - Health check
- `GET /status` - Agent status and metrics

### NATS Topics

- `segmentation.metrics.{host_id}` - Metrics data
- `segmentation.events.{host_id}` - Segmentation events
- `segmentation.policy_updates.{host_id}` - Policy updates
- `segmentation.system.{host_id}` - System events

### Metrics

The agent publishes various metrics:

- `packets_total` - Total packets processed
- `packets_allowed` - Packets allowed by policy
- `packets_dropped` - Packets dropped by policy
- `connections_blocked` - Connections blocked
- `programs_loaded` - eBPF programs loaded
- `policies_active` - Active policies

## 🔍 Troubleshooting

### Common Issues

1. **eBPF programs fail to load**
   - Check kernel version (5.4+ required)
   - Verify BTF availability: `bpftool btf dump file /sys/kernel/btf/vmlinux`
   - Ensure running as root

2. **NATS connection failed**
   - Verify NATS server is running
   - Check NATS_URL environment variable
   - Test connectivity: `telnet <nats-host> 4222`

3. **Policy evaluation errors**
   - Check policy JSON format
   - Verify rule conditions
   - Enable debug logging

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG=debug
./segmentation-agent
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Cilium eBPF](https://github.com/cilium/ebpf) - Go eBPF library
- [NATS](https://nats.io/) - Messaging system
- [Linux eBPF](https://ebpf.io/) - Extended Berkeley Packet Filter
