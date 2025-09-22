# Aegis Agent - Enterprise Security Platform

A comprehensive, modular security agent with advanced network segmentation, process monitoring, and threat intelligence capabilities.

## 🏗️ Architecture

```
aegis-agent/
├── agents/aegis/           # Core agent implementation
├── backend/                # Backend API services
├── bpf/                    # eBPF programs and maps
├── docs/                   # Documentation
├── examples/               # Configuration examples
├── scripts/                # Deployment and utility scripts
└── artifacts/              # Build artifacts and binaries
```

## 🚀 Quick Start

### Prerequisites
- Go 1.21+
- Linux kernel 5.4+ (for eBPF)
- Root privileges (for eBPF operations)

### Build and Run
```bash
# Build the agent
cd agents/aegis
go build -o aegis-agent ./cmd/aegis/main.go

# Run with basic configuration
sudo ./aegis-agent --config=examples/configs/basic.yaml
```

## 📚 Documentation

### Core Documentation
- [**Implementation Plan**](docs/plans/COMPREHENSIVE_AGENT_MODULARIZATION_PLAN.md) - Complete modularization and communication plan
- [**Agent Evolution**](docs/plans/AGENT_EVOLUTION_IMPLEMENTATION_PLAN.md) - 4-phase evolution roadmap
- [**Size Analysis**](docs/analysis/AGENT_SIZE_ANALYSIS.md) - Size optimization analysis

### Guides
- [**Artifact Processing**](docs/guides/AGENT_ARTIFACT_PROCESSING_GUIDE.md) - Backend artifact processing
- [**Backend Interface**](docs/guides/AGENT_TEAM_BACKEND_CLARIFICATION.md) - Backend interface selection
- [**Enhanced Interaction**](docs/guides/ENHANCED_AGENT_BACKEND_INTERACTION.md) - Agent-backend interaction

### Communication
- [**Secure Communication**](docs/communication/SECURE_AGENT_BACKEND_COMMUNICATION.md) - Bidirectional WebSocket communication

### Deployment
- [**ARM64 Deployment**](docs/deployment/README_ARM64_DEPLOYMENT.md) - ARM64 deployment guide
- [**Agent Cap5B**](docs/deployment/README_AGENT_CAP5B.md) - Capability 5B implementation
- [**Next Steps**](docs/deployment/README_NEXT_STEPS.md) - Implementation next steps

## 🔧 Features

### Core Security
- **Network Segmentation**: eBPF-based network policy enforcement
- **Process Monitoring**: Real-time process tracking and analysis
- **Policy Validation**: Comprehensive policy validation and conflict detection
- **Rollback Mechanisms**: Intelligent rollback planning and execution

### Advanced Capabilities
- **Dependency Analysis**: System dependency mapping and analysis
- **Threat Intelligence**: Real-time threat intelligence integration
- **Anomaly Detection**: Behavioral anomaly detection and alerting
- **Policy Simulation**: Policy impact simulation and testing

### Communication
- **Secure WebSocket**: Encrypted bidirectional communication
- **Firewall Friendly**: Agent-initiated connections
- **Real-time Events**: Live event streaming and command processing
- **Channel-based Routing**: Organized communication channels

## 📦 Modular Architecture

The agent supports modular deployment based on requirements:

### Core Agent (5,000 lines)
- Essential security functions
- Basic policy engine
- eBPF management
- Secure communication

### Optional Modules
- **Analysis Module**: Dependency analysis, policy simulation
- **Observability Module**: Process monitoring, anomaly detection
- **Threat Intelligence Module**: Threat intel integration
- **Advanced Policies Module**: Process-level policies

## 🚀 Deployment Scenarios

### Minimal Agent
```yaml
core:
  enabled: true
modules:
  analysis: {enabled: false}
  observability: {enabled: false}
  threat_intelligence: {enabled: false}
  advanced_policies: {enabled: false}
```

### Standard Agent
```yaml
core:
  enabled: true
modules:
  observability: {enabled: true}
  # Other modules disabled
```

### Full Agent
```yaml
core:
  enabled: true
modules:
  analysis: {enabled: true}
  observability: {enabled: true}
  threat_intelligence: {enabled: true}
  advanced_policies: {enabled: true}
```

## 🔐 Security Features

- **End-to-End Encryption**: ChaCha20-Poly1305 encryption
- **Digital Signatures**: Ed25519 message integrity
- **Mutual Authentication**: Agent and backend verification
- **Perfect Forward Secrecy**: Key rotation for security
- **Audit Logging**: Comprehensive security event logging

## 📊 Performance

- **Startup Time**: < 2 seconds
- **Memory Usage**: < 50 MB (core), < 100 MB (full)
- **Binary Size**: < 10 MB (optimized build)
- **Communication Latency**: < 100ms

## 🛠️ Development

### Project Structure
```
agents/aegis/
├── cmd/aegis/              # Main entry points
├── internal/
│   ├── core/               # Core agent logic
│   ├── communication/      # Backend communication
│   ├── enforcement/        # Policy enforcement
│   ├── observability/      # Process monitoring
│   ├── analysis/           # Dependency analysis
│   ├── policy/             # Policy management
│   └── telemetry/          # Event logging
└── pkg/models/             # Data models
```

### Building
```bash
# Core agent only
go build -tags="core" -o aegis-agent-core

# With observability
go build -tags="core,observability" -o aegis-agent-obs

# Full agent
go build -tags="all" -o aegis-agent-full
```

## 📈 Roadmap

### Phase 1: Core Agent Extraction ✅
- Extract essential components
- Remove redundant code
- Basic build optimization

### Phase 2: Modular Architecture 🚧
- Create plugin system
- Extract optional modules
- Dynamic loading capability

### Phase 3: Secure Communication 🚧
- WebSocket implementation
- Encryption and authentication
- Channel-based routing

### Phase 4: Integration & Optimization 📋
- Module integration
- Performance optimization
- Comprehensive testing

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Documentation**: See `docs/` directory
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

---

**Aegis Agent** - Enterprise-grade security for modern infrastructure.