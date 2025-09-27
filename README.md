# Aegis Agent

A modular, enterprise-grade security agent with dynamic backend control capabilities.

## 🚀 **Features**

- **✅ Modular Architecture**: 6 specialized modules with dynamic control
- **✅ Backend Module Control**: Real-time start/stop/enable/disable modules
- **✅ WebSocket Communication**: Secure, encrypted backend communication
- **✅ Zero Downtime**: Module changes without agent restart
- **✅ Multi-Platform**: Linux ARM64, AMD64, macOS support
- **✅ Production Ready**: Comprehensive error handling and logging

## 📋 **Available Modules**

| Module | Purpose | Default Status |
|--------|---------|----------------|
| `telemetry` | Enhanced metrics collection | Running |
| `websocket_communication` | Backend communication | Running |
| `observability` | System observability | Running |
| `analysis` | Dependency analysis | Stopped |
| `threat_intelligence` | Threat detection | Stopped |
| `advanced_policy` | Policy enforcement | Stopped |

## 🏗️ **Architecture**

The Aegis Agent uses a modular architecture where all modules are shipped with the agent but can be dynamically controlled by the backend:

```
Backend → WebSocket → WebSocketCommunicationModule → ModuleManager → Target Module
```

## 🚀 **Quick Start**

### Build
```bash
cd agents/aegis
make build
```

### Run
```bash
./aegis-agent --agent-id "my-agent" --backend-url "ws://backend:8080/ws/agent" --log-level debug
```

### Module Control
```bash
# Test module control
python3 test_module_control.py
```

## 📚 **Documentation**

📖 **[Complete Documentation](./docs/README.md)** - Organized documentation index

### Quick Links:
- **🚀 Production Setup**: [`docs/guides/PRODUCTION_READINESS_CHECKLIST.md`](./docs/guides/PRODUCTION_READINESS_CHECKLIST.md)
- **🔌 Connection Guide**: [`docs/guides/AGENT_TEAM_CONNECTION_GUIDE.md`](./docs/guides/AGENT_TEAM_CONNECTION_GUIDE.md)
- **🔧 Troubleshooting**: [`docs/guides/AGENT_TROUBLESHOOTING_GUIDE.md`](./docs/guides/AGENT_TROUBLESHOOTING_GUIDE.md)
- **📡 WebSocket Protocol**: [`docs/api/WEBSOCKET_PROTOCOL_SPECIFICATION.md`](./docs/api/WEBSOCKET_PROTOCOL_SPECIFICATION.md)
- **🏗️ Architecture**: [`docs/architecture/MODULAR_ARCHITECTURE_SUMMARY.md`](./docs/architecture/MODULAR_ARCHITECTURE_SUMMARY.md)
- **🧪 Testing**: [`docs/testing/AGENT_CONNECTION_TEST.py`](./docs/testing/AGENT_CONNECTION_TEST.py)

## 🔧 **Build Targets**

```bash
make build              # Build for current platform
make build-linux-arm64  # Build for Linux ARM64
make build-linux-amd64  # Build for Linux AMD64
make build-darwin-arm64 # Build for macOS ARM64
make clean              # Clean build artifacts
make help               # Show all targets
```

## 🎯 **Module Control Commands**

The backend can control modules via WebSocket commands:

```json
// List all modules
{"type": "list_modules"}

// Start a module
{"type": "start_module", "module_id": "analysis"}

// Stop a module
{"type": "stop_module", "module_id": "threat_intelligence"}

// Get module status
{"type": "get_module_status", "module_id": "observability"}
```

## 🔒 **Security**

- **Authentication**: Ed25519 signature verification
- **Encryption**: ChaCha20-Poly1305 message encryption
- **Authorization**: Backend-only module control access
- **Rate Limiting**: Built-in command throttling

## 📊 **Performance**

- **Module Control**: < 1ms per command
- **Module Startup**: 100-500ms depending on module
- **Memory Usage**: ~14MB total with all modules
- **Zero Downtime**: Module changes without service interruption

## 🛠️ **Development**

### Prerequisites
- Go 1.21+
- Linux kernel 4.18+ (for eBPF)
- clang, llvm, bpftool (for eBPF compilation)

### Testing
```bash
make test              # Test build
make test-modules      # Test module control
```

## 📈 **Status**

- **✅ Core Agent**: Production ready
- **✅ Module System**: Fully implemented
- **✅ Backend Control**: Complete
- **✅ Documentation**: Comprehensive
- **✅ Multi-Platform**: Linux ARM64/AMD64, macOS

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 **License**

MIT License - see LICENSE file for details.

---

**The Aegis Agent provides enterprise-grade security with dynamic module control capabilities!** 🚀