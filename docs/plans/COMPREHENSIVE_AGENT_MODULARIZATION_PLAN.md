# Comprehensive Aegis Agent Modularization & Communication Plan

## 🎯 Executive Summary

This comprehensive plan addresses two critical needs:
1. **Modular Architecture**: Reduce agent size from 48,474 lines to ~15,000 lines (70% reduction)
2. **Secure Communication**: Implement bidirectional agent-backend communication for firewall environments

## 📊 Current State Analysis

### Agent Size Metrics
- **Total Go Files**: 65 files
- **Total Lines of Code**: 48,474 lines
- **Source Size**: 1.4 MB (1,430,512 bytes)
- **Directory Size**: 45 MB (includes dependencies)

### Communication Gaps
- **Current**: Simple polling-based communication
- **Missing**: Bidirectional real-time communication
- **Problem**: Firewall environments block inbound connections
- **Need**: Agent-initiated persistent secure connection

## 🏗️ Unified Architecture Design

### Core Principles
1. **Modular Design**: Core agent + optional modules
2. **Secure Communication**: Agent-initiated bidirectional WebSocket
3. **Firewall Friendly**: Outbound connections only
4. **Enterprise Ready**: Scalable, maintainable, secure

### Target Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    Aegis Agent (Modular)                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │    Core     │  │  Analysis   │  │Observability│  │ Threat  │ │
│  │   Module    │  │   Module    │  │   Module    │  │ Module  │ │
│  │ (Required)  │  │(Optional)   │  │(Optional)   │  │(Optional)│ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
├─────────────────────────────────────────────────────────────────┤
│              Secure Communication Layer                         │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │        WebSocket + Encryption + Authentication             │ │
│  └─────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                    eBPF Runtime Layer                           │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │        Policy Enforcement + Process Monitoring             │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Backend (Cloud)                             │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │        WebSocket Gateway + Policy Management               │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 Implementation Phases

---

## 🚀 PHASE 1: CORE AGENT EXTRACTION (Week 1)
**Priority: CRITICAL - Foundation for everything else**

### 1.1 Extract Core Components (~5,000 lines)
**Goal**: Create minimal, essential agent functionality

#### Core Module Structure
```
agents/aegis/
├── cmd/aegis/main.go                    # Main entry point (~200 lines)
├── internal/
│   ├── core/
│   │   ├── agent.go                    # Core agent logic (~800 lines)
│   │   ├── policy_engine.go            # Basic policy engine (~600 lines)
│   │   └── ebpf_manager.go             # eBPF program management (~500 lines)
│   ├── communication/
│   │   ├── client.go                   # Backend communication (~400 lines)
│   │   └── secure_connection.go        # Secure WebSocket (~700 lines)
│   ├── enforcement/
│   │   ├── enforcer.go                 # Policy enforcement (~300 lines)
│   │   └── maps.go                     # eBPF map management (~400 lines)
│   └── telemetry/
│       ├── events.go                   # Event definitions (~200 lines)
│       └── logger.go                   # Basic logging (~300 lines)
└── pkg/models/
    └── policy.go                       # Policy data structures (~200 lines)
```

#### Tasks
- [ ] **Extract Core Logic**: Move essential functionality to core module
- [ ] **Simplify Policy Engine**: Keep only basic IP-based policies
- [ ] **Basic eBPF Management**: Essential map operations only
- [ ] **Simple Communication**: Basic polling + WebSocket foundation
- [ ] **Essential Telemetry**: Core events and logging only

#### Success Criteria
- Core agent builds and runs independently
- Size reduced to ~5,000 lines
- Binary size < 5 MB
- Memory usage < 20 MB

### 1.2 Remove Redundant Code (~10,000 lines reduction)
**Goal**: Eliminate duplicate and unused code

#### Tasks
- [ ] **Consolidate Main Files**: Keep only `main.go`, remove others
- [ ] **Merge Duplicate Structs**: Consolidate similar data structures
- [ ] **Remove Unused Code**: Clean up commented and dead code
- [ ] **Optimize Imports**: Remove unused dependencies
- [ ] **Simplify Algorithms**: Reduce complex logic where possible

#### Files to Remove/Consolidate
- `main_ubuntu_*.go` → Keep only `main.go`
- Duplicate policy structures → Single policy model
- Unused telemetry functions → Essential events only
- Redundant eBPF code → Core operations only

---

## 🔧 PHASE 2: MODULAR ARCHITECTURE (Week 2)
**Priority: HIGH - Enable flexible deployments**

### 2.1 Create Module System (~2,000 lines)
**Goal**: Implement plugin architecture for optional modules

#### Module Interface
```go
type Module interface {
    Name() string
    Version() string
    Initialize(config map[string]interface{}) error
    Start() error
    Stop() error
    IsEnabled() bool
    Dependencies() []string
}

type ModuleManager struct {
    modules map[string]Module
    config  map[string]interface{}
    mu      sync.RWMutex
}
```

#### Module Management
- [ ] **Plugin Architecture**: Dynamic module loading
- [ ] **Configuration System**: Module-specific config
- [ ] **Dependency Resolution**: Module dependency management
- [ ] **Lifecycle Management**: Start/stop/restart modules
- [ ] **Health Monitoring**: Module health checks

### 2.2 Extract Optional Modules (~10,000 lines)
**Goal**: Move advanced features to loadable modules

#### Analysis Module (~3,000 lines)
```
agents/aegis/modules/analysis/
├── dependency_analyzer.go              # System dependency analysis
├── policy_simulator.go                 # Policy impact simulation
├── rollback_planner.go                 # Intelligent rollback planning
└── visualization.go                    # Dependency graph visualization
```

#### Observability Module (~3,000 lines)
```
agents/aegis/modules/observability/
├── process_monitor.go                  # Process monitoring
├── service_discovery.go                # Service discovery
├── anomaly_detector.go                 # Behavioral anomaly detection
└── advanced_monitor.go                 # Advanced monitoring
```

#### Threat Intelligence Module (~2,000 lines)
```
agents/aegis/modules/threat_intelligence/
├── threat_intelligence.go              # Threat intel integration
├── ioc_matcher.go                      # Indicator of compromise matching
└── threat_analyzer.go                  # Threat analysis
```

#### Advanced Policies Module (~2,000 lines)
```
agents/aegis/modules/advanced_policies/
├── process_policies.go                 # Process-level policies
├── file_policies.go                    # File access policies
├── advanced_engine.go                  # Advanced policy engine
└── policy_templates.go                 # Policy templates
```

### 2.3 Module Configuration System
**Goal**: Enable flexible module loading based on deployment needs

#### Configuration File
```yaml
# aegis-config.yaml
core:
  enabled: true
  modules:
    - name: "basic_policy_engine"
    - name: "ebpf_manager"
    - name: "communication"

modules:
  analysis:
    enabled: false  # Load on demand
    config:
      analysis_interval: "30s"
      max_dependencies: 1000
      
  observability:
    enabled: true   # Always loaded
    config:
      process_monitoring: true
      service_discovery: true
      anomaly_detection: false
      
  threat_intelligence:
    enabled: false  # Load on demand
    config:
      ioc_sources: ["threat_feeds"]
      update_interval: "1h"
      
  advanced_policies:
    enabled: false  # Load on demand
    config:
      process_policies: true
      file_policies: false
```

---

## 🔐 PHASE 3: SECURE COMMUNICATION (Week 3)
**Priority: HIGH - Enable real-time collaboration**

### 3.1 WebSocket Gateway Implementation
**Goal**: Implement bidirectional communication infrastructure

#### Backend WebSocket Gateway
```
backend/
├── gateway/
│   ├── websocket_gateway.go            # WebSocket server
│   ├── agent_manager.go                # Agent connection management
│   ├── message_router.go               # Message routing
│   └── authentication.go               # Agent authentication
├── communication/
│   ├── channels.go                     # Communication channels
│   ├── message_types.go                # Message definitions
│   └── encryption.go                   # Message encryption
└── api/
    ├── policy_api.go                   # Policy management API
    ├── investigation_api.go            # Investigation API
    └── telemetry_api.go                # Telemetry API
```

#### Agent Communication Layer
```
agents/aegis/internal/communication/
├── secure_connection.go                # WebSocket client
├── message_router.go                   # Message routing
├── encryption.go                       # Message encryption
├── authentication.go                   # Agent authentication
└── channels.go                         # Communication channels
```

### 3.2 Communication Channels
**Goal**: Implement organized communication channels

#### Agent → Backend Channels
- `agent.{agent_id}.policies` - Policy updates and status
- `agent.{agent_id}.anomalies` - Real-time anomaly alerts
- `agent.{agent_id}.threats` - Threat intelligence matches
- `agent.{agent_id}.processes` - Process events and monitoring
- `agent.{agent_id}.dependencies` - Dependency analysis data
- `agent.{agent_id}.tests` - Policy test results
- `agent.{agent_id}.rollbacks` - Rollback status and plans
- `agent.{agent_id}.heartbeat` - Health and status updates
- `agent.{agent_id}.logs` - Audit and system logs

#### Backend → Agent Channels
- `backend.{agent_id}.policies` - Policy commands and updates
- `backend.{agent_id}.investigations` - Investigation requests
- `backend.{agent_id}.threats` - Threat intelligence updates
- `backend.{agent_id}.processes` - Process policy commands
- `backend.{agent_id}.tests` - Test execution commands
- `backend.{agent_id}.rollbacks` - Rollback commands

### 3.3 Security Implementation
**Goal**: Ensure secure, authenticated communication

#### Encryption & Authentication
- **ChaCha20-Poly1305**: High-performance encryption
- **Ed25519 Signatures**: Digital signatures for integrity
- **Mutual Authentication**: Both parties verify each other
- **Perfect Forward Secrecy**: Key rotation for security
- **Session Management**: Token-based authentication

#### Message Security
```go
type SecureMessage struct {
    ID        string            `json:"id"`
    Type      MessageType       `json:"type"`
    Channel   string            `json:"channel"`
    Payload   string            `json:"payload"`      // Encrypted
    Timestamp int64             `json:"timestamp"`
    Nonce     string            `json:"nonce"`
    Signature string            `json:"signature"`
    Headers   map[string]string `json:"headers"`
}
```

---

## 🔄 PHASE 4: INTEGRATION & OPTIMIZATION (Week 4)
**Priority: MEDIUM - Polish and optimize**

### 4.1 Module Integration
**Goal**: Seamlessly integrate modules with core agent

#### Tasks
- [ ] **Module Loading**: Dynamic module loading based on config
- [ ] **Dependency Resolution**: Handle module dependencies
- [ ] **Error Handling**: Graceful module failure handling
- [ ] **Resource Management**: Module resource limits
- [ ] **Health Monitoring**: Module health checks

### 4.2 Communication Integration
**Goal**: Integrate secure communication with all modules

#### Tasks
- [ ] **Event Streaming**: Stream events from modules to backend
- [ ] **Command Processing**: Process backend commands in modules
- [ ] **State Synchronization**: Sync module state with backend
- [ ] **Error Reporting**: Report module errors to backend
- [ ] **Performance Monitoring**: Monitor communication performance

### 4.3 Build Optimization
**Goal**: Optimize build size and performance

#### Build Targets
```bash
# Core agent only
go build -tags="core" -o aegis-agent-core

# Core + observability
go build -tags="core,observability" -o aegis-agent-obs

# Full agent with all modules
go build -tags="all" -o aegis-agent-full
```

#### Optimization Flags
```bash
# Size optimization
go build -ldflags="-s -w" -trimpath -buildmode=pie

# Binary stripping
strip aegis-agent

# Optional compression
upx --best aegis-agent
```

---

## 📊 Size Targets by Phase

### Phase 1: Core Agent (5,000 lines)
| Component | Current | Target | Reduction |
|-----------|---------|--------|-----------|
| Main Entry | 1,000 | 200 | 80% |
| Policy Engine | 1,500 | 800 | 47% |
| eBPF Management | 1,200 | 600 | 50% |
| Communication | 1,000 | 500 | 50% |
| Telemetry | 800 | 400 | 50% |
| Models | 500 | 200 | 60% |
| **Total** | **6,000** | **2,700** | **55%** |

### Phase 2: Optional Modules (10,000 lines)
| Module | Current | Target | Reduction |
|--------|---------|--------|-----------|
| Analysis | 2,000 | 1,500 | 25% |
| Observability | 1,800 | 1,200 | 33% |
| Threat Intel | 1,000 | 800 | 20% |
| Visualization | 1,000 | 600 | 40% |
| Advanced Policies | 1,500 | 1,000 | 33% |
| **Total** | **7,300** | **5,100** | **30%** |

### Phase 3: Communication (2,000 lines)
| Component | Lines | Purpose |
|-----------|-------|---------|
| WebSocket Client | 700 | Agent-side communication |
| Message Router | 400 | Message routing and handling |
| Encryption | 300 | Message encryption/decryption |
| Authentication | 300 | Agent authentication |
| Channels | 300 | Communication channels |
| **Total** | **2,000** | **Communication layer** |

## 🎯 Final Architecture

### Core Agent (5,000 lines)
- Essential security functions
- Basic policy engine
- eBPF management
- Secure communication
- Essential telemetry

### Optional Modules (10,000 lines)
- Analysis module (3,000 lines)
- Observability module (3,000 lines)
- Threat intelligence module (2,000 lines)
- Advanced policies module (2,000 lines)

### Communication Layer (2,000 lines)
- WebSocket client/server
- Message encryption
- Authentication
- Channel management

### Total: ~17,000 lines (65% reduction from current 48,474)

## 🚀 Deployment Scenarios

### Scenario 1: Minimal Agent (5,000 lines)
```yaml
core:
  enabled: true
modules:
  analysis: {enabled: false}
  observability: {enabled: false}
  threat_intelligence: {enabled: false}
  advanced_policies: {enabled: false}
```
**Use Case**: Basic network segmentation, minimal resources

### Scenario 2: Standard Agent (8,000 lines)
```yaml
core:
  enabled: true
modules:
  analysis: {enabled: false}
  observability: {enabled: true}
  threat_intelligence: {enabled: false}
  advanced_policies: {enabled: false}
```
**Use Case**: Network segmentation + process monitoring

### Scenario 3: Full Agent (17,000 lines)
```yaml
core:
  enabled: true
modules:
  analysis: {enabled: true}
  observability: {enabled: true}
  threat_intelligence: {enabled: true}
  advanced_policies: {enabled: true}
```
**Use Case**: Complete security platform, enterprise deployment

## 📈 Success Metrics

### Size Metrics
- **Source Code**: 48,474 → 17,000 lines (65% reduction)
- **Binary Size**: < 10 MB (optimized build)
- **Memory Usage**: < 50 MB runtime
- **Deployment Package**: < 20 MB (compressed)

### Performance Metrics
- **Startup Time**: < 2 seconds
- **Module Loading**: < 1 second per module
- **Communication Latency**: < 100ms
- **CPU Usage**: < 5% idle

### Security Metrics
- **Encryption**: All communications encrypted
- **Authentication**: Mutual authentication required
- **Integrity**: Message signatures verified
- **Audit**: All actions logged and auditable

## 🎉 Benefits

### 1. **Flexible Deployment**
- Right-sized agent for different use cases
- Load only needed modules
- Easy to maintain and update

### 2. **Secure Communication**
- Real-time bidirectional communication
- Firewall-friendly architecture
- Enterprise-grade security

### 3. **Maintainable Codebase**
- Modular architecture
- Clear separation of concerns
- Easy to test and debug

### 4. **Scalable Platform**
- Add new modules easily
- Support multiple deployment scenarios
- Future-proof architecture

## 🚀 Next Steps

1. **Start Phase 1**: Extract core agent components
2. **Implement Module System**: Create plugin architecture
3. **Build Communication Layer**: WebSocket + encryption
4. **Integrate Everything**: Seamless module integration
5. **Optimize & Test**: Performance and security testing

This comprehensive plan addresses both the size concerns and the communication needs while maintaining all the advanced capabilities we've built! 🎯
