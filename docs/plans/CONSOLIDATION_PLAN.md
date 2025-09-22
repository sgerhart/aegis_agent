# Segmentation Agent Consolidation Plan

## Overview
Consolidate the `segmentation-agent-go` functionality into the main `aegis-ubuntu-production` agent to create a single, lightweight, comprehensive agent.

## Features to Integrate

### 1. CO-RE Build System
- **Source**: `agents/segmentation-agent-go/internal/build/core_builder.go`
- **Integration**: Add to `agents/aegis/internal/build/`
- **Purpose**: Runtime eBPF program compilation with clang/llvm

### 2. Enhanced Policy Engine
- **Source**: `agents/segmentation-agent-go/internal/policy/engine.go`
- **Integration**: Enhance existing `agents/aegis/internal/policy/` or merge
- **Purpose**: Rule-based policy evaluation and management

### 3. Capability Probing
- **Source**: `agents/segmentation-agent-go/internal/capability/probe.go`
- **Integration**: Add to `agents/aegis/internal/capability/`
- **Purpose**: System capability detection and reporting

### 4. Advanced Observability
- **Source**: `agents/segmentation-agent-go/internal/observability/observability.go`
- **Integration**: Enhance `agents/aegis/internal/telemetry/`
- **Purpose**: Enhanced NATS publishing and metrics collection

### 5. eBPF Templates
- **Source**: `agents/segmentation-agent-go/ebpf/templates/`
- **Integration**: Move to `bpf/templates/` or `agents/aegis/ebpf/templates/`
- **Purpose**: XDP, TC, and cgroup eBPF program templates

## Consolidation Benefits

### ✅ Single Agent Deployment
- One binary to manage
- One service to monitor  
- One configuration to maintain

### ✅ Reduced Resource Usage
- Single process footprint
- Shared memory and CPU
- One HTTP port

### ✅ Simplified Operations
- Single systemd service
- Unified logging
- Single health endpoint

### ✅ Enhanced Capabilities
- Combined: Registration + eBPF + Segmentation + Safety + Telemetry
- All Cap 7.9 and Cap 7.10 features in one place

## Implementation Steps

1. **Copy Core Components**
   ```bash
   cp -r agents/segmentation-agent-go/internal/build agents/aegis/internal/
   cp -r agents/segmentation-agent-go/internal/capability agents/aegis/internal/
   cp -r agents/segmentation-agent-go/ebpf/templates bpf/
   ```

2. **Integrate Policy Engine**
   - Merge rule-based policy features into existing policy system
   - Add XDP/TC policy types

3. **Enhance Telemetry**
   - Add segmentation-specific metrics
   - Implement NATS publishing from segmentation agent

4. **Add CO-RE Builder**
   - Runtime eBPF compilation capabilities
   - Template-based program generation

5. **Update Main Agent**
   - Add command-line flags for segmentation features
   - Integrate new components into main loop

## Final Agent Capabilities

### 🎯 One Agent, All Features:
- **Backend Integration**: Registration, NATS, Actions-API
- **eBPF Enforcement**: TC, XDP, cgroup programs
- **Policy Management**: File-based + rule-based + dynamic
- **Safety Features**: Crypto verification, dry-run, rollback
- **Observability**: Comprehensive metrics and events
- **Runtime Compilation**: CO-RE eBPF program building
- **Capability Detection**: System probing and reporting

## Configuration

### Environment Variables (All-in-One)
```bash
# Backend Integration
ACTIONS_API_URL=http://backend:8083
NATS_URL=nats://backend:4222
AGENT_REGISTRY_URL=http://registry:8090

# eBPF Features  
AEGIS_EBPF=true
AEGIS_SEGMENTATION=true
AEGIS_BUILD_PROGRAMS=true

# Build Environment
CLANG_PATH=/usr/bin/clang
BPFTOOL_PATH=/usr/sbin/bpftool
BTF_PATH=/sys/kernel/btf/vmlinux

# Safety Features
AEGIS_DRY_RUN=false
AEGIS_MTLS=true
AEGIS_TRUSTSTORE=/etc/aegis/truststore.json
```

## Cleanup After Integration

1. Remove `agents/segmentation-agent-go/` directory
2. Remove segmentation service file
3. Update documentation to reference single agent
4. Update deployment scripts

## Result: Lightweight, Comprehensive Agent

- **Binary Size**: ~12-15MB (vs 10MB + 5MB = 15MB for two agents)
- **Memory Usage**: ~50-100MB (vs ~80-150MB for two agents)  
- **CPU Usage**: Minimal overhead for integrated features
- **Deployment**: Single systemd service
- **Management**: One agent to rule them all!
