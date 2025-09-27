# Module Connectivity & Backend Service Specification

## 🔌 **Module-to-Backend Connectivity Matrix**

### **Communication Channels**

| Module | Backend Service | Channel | Message Type | Frequency | Purpose |
|--------|----------------|---------|--------------|-----------|---------|
| **Core** | Registry | `agent.registry` | Registration | Once | Agent registration |
| **Core** | Actions API | `agent.control` | Commands | On-demand | Module control |
| **Telemetry** | Actions API | `agent.telemetry` | Metrics | 30s | Performance data |
| **WebSocket Comm** | Gateway | `auth` | Authentication | Once | Session establishment |
| **WebSocket Comm** | Gateway | `heartbeat` | Heartbeat | 30s | Connection health |
| **Observability** | Actions API | `agent.observability` | Events | Real-time | System events |
| **Analysis** | Actions API | `agent.analysis` | Reports | On-demand | Analysis results |
| **Threat Intel** | Actions API | `agent.threat` | Alerts | Real-time | Threat detection |
| **Advanced Policy** | Actions API | `agent.policy` | Enforcement | On-demand | Policy actions |

---

## 🏗️ **Backend Service Architecture**

### **WebSocket Gateway (Port 8080)**
```
┌─────────────────────────────────────────────────────────────────┐
│                    WebSocket Gateway                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │    Auth     │  │   Message   │  │ Connection  │  │Encryption│ │
│  │  Service    │  │   Router    │  │  Manager    │  │ Service │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │ Heartbeat   │  │   Channel   │  │   Session   │  │ Message │ │
│  │  Monitor    │  │  Manager    │  │   Store     │  │  Queue  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### **Backend Services**
```
┌─────────────────────────────────────────────────────────────────┐
│                      Backend Services                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │   Actions   │  │  Registry   │  │    NATS     │  │Artifact │ │
│  │     API     │  │  Service    │  │  Message    │  │ Storage │ │
│  │             │  │             │  │    Queue    │  │ Service │ │
│  │ - Commands  │  │ - Agent Reg │  │ - Delivery  │  │ - Policy│ │
│  │ - Policies  │  │ - Sessions  │  │ - Routing   │  │ - Config│ │
│  │ - Responses │  │ - Health    │  │ - Queuing   │  │ - State │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │   Policy    │  │   Threat    │  │  Analytics  │  │  Audit  │ │
│  │   Engine    │  │Intelligence │  │   Engine    │  │  Log    │ │
│  │             │  │   Service   │  │             │  │ Service │ │
│  │ - Validation│  │ - IOCs      │  │ - Metrics   │  │ - Events│ │
│  │ - Enforcement│ │ - Feeds     │  │ - Reports   │  │ - Compliance│ │
│  │ - Rollback  │  │ - Response  │  │ - Dashboards│  │ - Alerts│ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📡 **Message Flow Patterns**

### **1. Agent Registration Flow**
```
Agent Core → WebSocket Gateway → Registry Service
    ↓              ↓                    ↓
[Register] → [Validate] → [Create Session] → [Return Credentials]
```

### **2. Module Control Flow**
```
Backend → WebSocket Gateway → WebSocket Comm Module → Module Manager → Target Module
    ↓              ↓                    ↓                    ↓              ↓
[Command] → [Route] → [Decrypt] → [Validate] → [Execute] → [Response]
```

### **3. Data Collection Flow**
```
Module → Telemetry Module → WebSocket Comm Module → WebSocket Gateway → Backend Service
    ↓              ↓                    ↓                    ↓              ↓
[Collect] → [Aggregate] → [Encrypt] → [Route] → [Store/Process]
```

### **4. Policy Enforcement Flow**
```
Backend → WebSocket Gateway → WebSocket Comm Module → Advanced Policy Module → eBPF System
    ↓              ↓                    ↓                    ↓                    ↓
[Policy] → [Route] → [Decrypt] → [Validate] → [Apply] → [Enforce]
```

---

## 🔐 **Security & Authentication Flow**

### **Initial Authentication**
```
1. Agent connects to WebSocket Gateway
2. Agent sends authentication message with Ed25519 signature
3. Gateway validates signature and creates session
4. Gateway returns session token and shared key
5. All subsequent messages encrypted with shared key
```

### **Message Security**
```
┌─────────────────────────────────────────────────────────────────┐
│                    Message Security Layer                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │   Ed25519   │  │ ChaCha20    │  │   Session   │  │ Message │ │
│  │  Signature  │  │ -Poly1305   │  │   Token     │  │  Auth   │ │
│  │             │  │ Encryption  │  │             │  │         │ │
│  │ - Verify    │  │ - Encrypt   │  │ - JWT       │  │ - Nonce │ │
│  │ - Sign      │  │ - Decrypt   │  │ - Expiry    │  │ - Timestamp│ │
│  │ - Validate  │  │ - Authenticate│ │ - Refresh   │  │ - Headers│ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 **Performance & Scalability**

### **Connection Limits**
- **WebSocket Connections**: 1 per agent (persistent)
- **Concurrent Modules**: Up to 10 modules per agent
- **Message Throughput**: 1000+ messages/second
- **Connection Pool**: Single connection with multiplexing

### **Resource Usage**
```
┌─────────────────────────────────────────────────────────────────┐
│                    Resource Usage Profile                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Core Agent:          4MB RAM,  5% CPU                         │
│  + Telemetry:        +2MB RAM, +10% CPU                        │
│  + WebSocket Comm:   +1MB RAM, +5% CPU                         │
│  + Observability:    +3MB RAM, +15% CPU                        │
│  + Analysis:         +2MB RAM, +20% CPU                        │
│  + Threat Intel:     +2MB RAM, +10% CPU                        │
│  + Advanced Policy:  +2MB RAM, +25% CPU                        │
│                                                                 │
│  Total (All Modules): 16MB RAM, 90% CPU                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔄 **Module Dependencies**

### **Dependency Graph**
```
Core Module (Base)
    ├── Telemetry Module
    ├── WebSocket Communication Module
    ├── Observability Module
    │   ├── Analysis Module
    │   │   └── Threat Intelligence Module
    │   └── Advanced Policy Module
    └── [Future Modules]
```

### **Startup Sequence**
```
1. Core Module (Always first)
2. WebSocket Communication Module
3. Telemetry Module
4. Observability Module
5. Analysis Module (if enabled)
6. Threat Intelligence Module (if enabled)
7. Advanced Policy Module (if enabled)
```

---

## 📋 **Channel Specifications**

### **Channel Naming Convention**
```
{service}.{module}.{action}
Examples:
- agent.telemetry.metrics
- agent.analysis.report
- agent.policy.enforce
- agent.threat.alert
```

### **Message Format**
```json
{
  "id": "unique_message_id",
  "type": "request|response|event",
  "channel": "agent.module.action",
  "payload": "base64_encoded_data",
  "timestamp": 1234567890,
  "nonce": "base64_encoded_nonce",
  "signature": "base64_encoded_signature",
  "headers": {
    "agent_id": "agent-001",
    "module_id": "telemetry",
    "session_token": "jwt_token"
  }
}
```

---

## 🎯 **Implementation Status**

### **✅ Implemented**
- Core Module System
- WebSocket Communication
- Basic Telemetry
- Module Management
- Authentication & Registration

### **⚠️ Partially Implemented**
- Observability (simulation only)
- Analysis (simulation only)
- Threat Intelligence (simulation only)
- Advanced Policy (simulation only)

### **❌ Not Implemented**
- Real eBPF Policy Enforcement
- Advanced Security Features
- Comprehensive Monitoring
- Automated Response Actions

This specification provides the complete technical details for implementing the full agent-backend communication system with all modules and services.
