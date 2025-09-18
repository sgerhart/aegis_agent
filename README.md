# 🛡️ AegisFlux Agent

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![eBPF](https://img.shields.io/badge/eBPF-Cilium-blue?style=flat&logo=linux)](https://cilium.io/)

A **An Exploratory eBPF agent** for the AegisFlux platform that runs on Linux hosts to manage and execute eBPF programs with enterprise-grade security, monitoring, and reliability features.

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Deployment](#-deployment)
- [Configuration](#-configuration)
- [Development](#-development)
- [API Reference](#-api-reference)
- [Contributing](#-contributing)
- [License](#-license)

## 🎯 Overview

AegisFlux Agent is a lightweight, secure host-side agent that:

- **Fetches** eBPF artifacts from a registry service
- **Verifies** digital signatures using Vault or development keys
- **Loads** CO-RE eBPF programs into the kernel (XDP, TC, LSM, kprobes)
- **Monitors** runtime performance with automatic rollback
- **Reports** telemetry and system capabilities via NATS
- **Provides** health and status APIs for operators

### Key Capabilities

- 🔒 **Security First**: Signature verification, capability restrictions, secure defaults
- ⚡ **High Performance**: Kernel-level eBPF execution with minimal overhead
- 🧠 **Autonomous**: TTL management, drift detection, automatic rollback
- 📡 **Observable**: Comprehensive telemetry and health monitoring
- 🐧 **Linux Native**: Works on bare metal, VMs, and Kubernetes nodes
- 🧩 **Modular**: Clean architecture with pluggable components

## ✨ Features

### Core Functionality
- **eBPF Program Loading**: CO-RE support with Cilium eBPF library
- **Signature Verification**: Vault integration + development key support
- **Registry Integration**: Artifact fetching and bundle download
- **Telemetry**: Real-time metrics and event reporting via NATS

### Security & Reliability
- **CPU Guard**: Automatic rollback on resource threshold breaches
- **Drift Detection**: File integrity monitoring and TTL management
- **Capability Probing**: System capability detection and reporting
- **Error Handling**: Comprehensive error recovery and logging

### Operations
- **Health Monitoring**: `/healthz` and `/status` endpoints
- **Systemd Integration**: Production-ready service management
- **Container Support**: Docker and Docker Compose deployment
- **Configuration**: Environment-based configuration management

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Registry      │    │   AegisFlux     │    │      NATS       │
│   Service       │◄───┤     Agent       ├───►│   Telemetry     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Linux Kernel  │
                       │   eBPF Programs │
                       └─────────────────┘
```

### Component Structure

```
agents/local-agent-go/
├── cmd/agent/                 # Main application entrypoint
├── internal/
│   ├── capability/           # System capability detection
│   ├── drift/                # File drift detection
│   ├── guard/                # CPU monitoring and rollback
│   ├── loader/               # eBPF program loading
│   ├── registry/             # Registry client
│   ├── status/               # Health and status API
│   ├── telemetry/            # NATS telemetry
│   └── verify/               # Signature verification
├── deploy/
│   └── systemd/              # Systemd service unit
├── Dockerfile                # Container build
├── docker-compose.yml        # Full stack deployment
└── DEPLOYMENT.md             # Deployment documentation
```

## 🚀 Quick Start

### Prerequisites

- **Linux kernel 4.15+** with eBPF support
- **Go 1.23+** (for building from source)
- **Root privileges** or appropriate capabilities (`CAP_BPF`, `CAP_NET_ADMIN`)
- **Registry service** and **NATS broker** access

### Build and Run

```bash
# Clone the repository
git clone https://github.com/sgerhart/aegis_agent.git
cd aegis_agent/agents/local-agent-go

# Build the agent
go mod tidy
go build -o aegisflux-agent ./cmd/agent

# Run with basic configuration
sudo ./aegisflux-agent
```

### Verify Installation

```bash
# Check health
curl -s http://localhost:7070/healthz
# {"ok":true}

# Check status
curl -s http://localhost:7070/status | jq .
# {
#   "loaded": {},
#   "capabilities": {...}
# }
```

## 🚀 Deployment

### Systemd (Recommended)

```bash
# Copy service file
sudo cp deploy/systemd/aegisflux-agent.service /etc/systemd/system/

# Configure environment
sudo systemctl edit aegisflux-agent
# Add your configuration:
# [Service]
# Environment=AGENT_REGISTRY_URL=http://your-registry:8090
# Environment=NATS_URL=nats://your-nats:4222
# Environment=AGENT_HOST_ID=your-host-id

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now aegisflux-agent
```

### Docker

```bash
# Build image
docker build -t aegisflux-agent .

# Run container
docker run -d \
  --name aegisflux-agent \
  --privileged \
  --cap-add=BPF \
  --cap-add=NET_ADMIN \
  -p 7070:7070 \
  -e AGENT_REGISTRY_URL=http://your-registry:8090 \
  -e NATS_URL=nats://your-nats:4222 \
  aegisflux-agent
```

### Docker Compose

```bash
# Start full stack
docker-compose up -d

# View logs
docker-compose logs -f aegisflux-agent
```

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_REGISTRY_URL` | `http://localhost:8090` | Registry service URL |
| `NATS_URL` | `nats://localhost:4222` | NATS broker URL |
| `AGENT_HTTP_ADDR` | `:7070` | HTTP server address |
| `AGENT_POLL_INTERVAL` | `10s` | Registry polling interval |
| `AGENT_BUNDLES_DIR` | `./bundles` | Bundle storage directory |
| `AGENT_HOST_ID` | `host-unknown` | Unique host identifier |
| `VAULT_URL` | `` | Vault server URL (optional) |
| `VAULT_TOKEN` | `` | Vault authentication token |
| `DEV_PUBLIC_KEY_PATH` | `` | Development public key path |

### Example Configuration

```bash
export AGENT_REGISTRY_URL="https://registry.company.com"
export NATS_URL="nats://nats.company.com:4222"
export AGENT_HOST_ID="web-server-01"
export VAULT_URL="https://vault.company.com"
export VAULT_TOKEN="$(vault token -format=raw)"
```

## 🧪 Development

### Project Structure

The agent is built with a modular architecture:

- **`cmd/agent/`**: Main application and orchestration
- **`internal/`**: Internal packages for specific functionality
- **`deploy/`**: Deployment configurations
- **`prompts/`**: Development specifications and requirements

### Development Workflow

1. **Use the provided prompts** in `prompts/agents/local-agent-go/` for guided development
2. **Test locally** with a privileged Docker container
3. **Monitor telemetry** with `nats sub agent.telemetry`
4. **Run tests** with the included end-to-end smoke tests

### Building from Source

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Build for different architectures
GOOS=linux GOARCH=amd64 go build -o aegisflux-agent-amd64 ./cmd/agent
GOOS=linux GOARCH=arm64 go build -o aegisflux-agent-arm64 ./cmd/agent
```

## 📊 API Reference

### Health Endpoints

#### `GET /healthz`
Basic health check endpoint.

**Response:**
```json
{"ok": true}
```

#### `GET /status`
Detailed status including loaded artifacts and system capabilities.

**Response:**
```json
{
  "loaded": {
    "artifact-123": "2025-09-17T14:32:11Z"
  },
  "capabilities": {
    "kernel_version": "5.4.0",
    "btf_available": true,
    "bpf_features": {...}
  }
}
```

### Telemetry Events

Events are published to the `agent.telemetry` NATS subject:

```json
{
  "host_id": "web-01",
  "artifact_id": "ebpf-2025-0007",
  "status": "loaded",
  "drops": 0,
  "errors": 0,
  "cpu_pct": 0.1,
  "verifier_msg": null,
  "ts": "2025-09-17T14:32:11Z"
}
```

## 🤝 Contributing

We welcome contributions! Please see our [Development Guide](DEPLOYMENT.md) for details on:

- Setting up the development environment
- Running tests and validation
- Submitting pull requests
- Code style and conventions

### Development Prompts

The project includes structured development prompts in `prompts/agents/local-agent-go/`:

1. **Scaffold Review** - Basic agent structure
2. **Registry Client** - Artifact fetching and download
3. **Signature Verification** - Vault and dev key support
4. **eBPF Loading** - Cilium eBPF integration
5. **Telemetry Events** - NATS event publishing
6. **Capability Probe** - System capability detection
7. **CPU Guard** - Resource monitoring and rollback
8. **Drift Detection** - File integrity monitoring
9. **Systemd & Container** - Deployment configurations
10. **E2E Testing** - End-to-end validation

## 📜 License

MIT © 2025 Dentro.io / AegisFlux Contributors

See [LICENSE](LICENSE) for details.