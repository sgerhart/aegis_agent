# Backend Architecture Clarification for Agent Team

## 🚨 CRITICAL CORRECTION

**The backend storage issues analysis contains a fundamental misunderstanding about our architecture. The backend IS fully implemented and working correctly.**

## 📊 Current Backend Architecture

### Two Separate Services

Our system uses **two distinct backend services** with different responsibilities:

#### 1. Actions API (Port 8083) - Agent Registration Only
- **Purpose:** Agent registration and management
- **Endpoints:**
  - `POST /agents/register/init` - Initialize agent registration
  - `POST /agents/register/complete` - Complete agent registration
  - `GET /agents` - List registered agents
  - `GET /agents/{uid}` - Get agent details
  - `GET /healthz` - Health check

#### 2. BPF Registry (Port 8090) - Artifact Storage & Management
- **Purpose:** eBPF artifact storage, assignment, and distribution
- **Endpoints:**
  - `POST /artifacts` - Create new artifacts
  - `GET /artifacts/{id}` - Get artifact metadata
  - `GET /artifacts/{id}/binary` - Download artifact binary
  - `GET /artifacts/for-host/{host_id}` - Get artifacts for specific host
  - `POST /assign/{artifact_id}/{host_id}` - Assign artifact to host
  - `DELETE /unassign/{artifact_id}/{host_id}` - Remove artifact assignment
  - `PUT /hosts/{artifact_id}` - Bulk host management
  - `GET /healthz` - Health check

## ✅ Backend Implementation Status

### BPF Registry - FULLY IMPLEMENTED

The BPF Registry service (`backend/bpf-registry/`) is **completely implemented** with:

#### Storage Layer
- **File:** `backend/bpf-registry/internal/store/file.go`
- **Status:** ✅ Complete
- **Features:**
  - Artifact storage with metadata
  - Binary data storage (tar.zst files)
  - Host assignment management
  - Checksum verification
  - Vault signature integration

#### API Layer
- **File:** `backend/bpf-registry/internal/api/http.go`
- **Status:** ✅ Complete
- **Features:**
  - All artifact management endpoints
  - Host assignment endpoints
  - Binary download endpoints
  - Error handling and validation

#### Data Models
- **File:** `backend/bpf-registry/internal/model/artifact.go`
- **Status:** ✅ Complete
- **Features:**
  - Artifact struct with all required fields
  - CreateArtifactRequest struct
  - Host assignment tracking

## 🔧 Agent Configuration Fix

### Current Issue
Your agent is likely configured to poll the **wrong service**:

```bash
# ❌ WRONG - This is the agent registration service
AGENT_REGISTRY_URL=http://localhost:8083

# ✅ CORRECT - This is the artifact storage service
AGENT_REGISTRY_URL=http://localhost:8090
```

### Required Changes

1. **Update Agent Configuration**
   ```bash
   # In your agent config file
   AGENT_REGISTRY_URL=http://localhost:8090
   ```

2. **Verify Service Endpoints**
   ```bash
   # Test artifact polling (correct service)
   curl http://localhost:8090/artifacts/for-host/192.168.193.129
   
   # Should return: {"artifacts":[],"total":0} (no artifacts assigned yet)
   ```

## 🧪 Testing the Complete Flow

### Step 1: Verify BPF Registry is Running
```bash
curl http://localhost:8090/healthz
# Expected: {"status":"healthy","timestamp":"...","version":"1.0.0"}
```

### Step 2: Create an Artifact
```bash
curl -X POST http://localhost:8090/artifacts \
  -H "Content-Type: application/json" \
  -d '{
    "name": "block-icmp-8888",
    "version": "1.0.0",
    "description": "Block ICMP ping traffic to 8.8.8.8",
    "type": "program",
    "architecture": "x86_64",
    "kernel_version": "5.4.0",
    "metadata": {
      "policy_type": "network_block",
      "target_ip": "8.8.8.8",
      "protocol": "icmp",
      "direction": "egress"
    },
    "tags": ["network", "security", "icmp"],
    "data": "base64_encoded_artifact_data"
  }'
```

### Step 3: Assign Artifact to Host
```bash
curl -X POST http://localhost:8090/assign/artifact_123/192.168.193.129
```

### Step 4: Test Agent Polling
```bash
curl http://localhost:8090/artifacts/for-host/192.168.193.129
# Should return the assigned artifact
```

### Step 5: Test Binary Download
```bash
curl http://localhost:8090/artifacts/artifact_123/binary
# Should return the tar.zst file
```

## 📋 Agent Implementation Requirements

### What Your Agent Needs to Do

1. **Configure Correct Service**
   - Point to BPF Registry (port 8090), not Actions API (port 8083)

2. **Poll for Artifacts**
   ```go
   // Correct endpoint
   GET /artifacts/for-host/{host_id}
   ```

3. **Download Binary Artifacts**
   ```go
   // Correct endpoint
   GET /artifacts/{artifact_id}/binary
   ```

4. **Process Artifacts**
   - Parse metadata JSON
   - Download tar.zst binary
   - Verify checksums and signatures
   - Load eBPF programs
   - Attach to network hooks

## 🎯 Expected Agent Flow

### Complete Working Flow

1. **Agent Registration** (Port 8083)
   ```bash
   POST http://localhost:8083/agents/register/init
   POST http://localhost:8083/agents/register/complete
   ```

2. **Artifact Polling** (Port 8090)
   ```bash
   GET http://localhost:8090/artifacts/for-host/{host_id}
   ```

3. **Artifact Download** (Port 8090)
   ```bash
   GET http://localhost:8090/artifacts/{artifact_id}/binary
   ```

4. **eBPF Deployment**
   - Agent processes downloaded artifact
   - Loads eBPF program into kernel
   - Attaches to network interface

## 🔍 Troubleshooting

### Common Issues

1. **404 Errors**
   - Check if you're using the correct port (8090 for artifacts)
   - Verify the endpoint path is correct

2. **Empty Artifact Lists**
   - This is correct if no artifacts are assigned to the host
   - Use the assignment API to assign artifacts

3. **Connection Errors**
   - Verify BPF Registry is running: `docker ps | grep bpf-registry`
   - Check port 8090 is accessible

### Debug Commands

```bash
# Check if BPF Registry is running
docker ps | grep bpf-registry

# Check BPF Registry logs
docker logs compose-bpf-registry-1

# Test all endpoints
curl http://localhost:8090/healthz
curl http://localhost:8090/artifacts/for-host/test
```

## 📚 Reference Documents

1. **AGENT_ARTIFACT_PROCESSING_GUIDE.md** - Complete artifact processing guide
2. **BACKEND_SPECIFICATION_FOR_AGENT.md** - Detailed backend API specification
3. **docker-compose.yml** - Service configuration and ports

## 🎯 Next Steps

1. **Update Agent Configuration** - Point to port 8090
2. **Test Basic Connectivity** - Verify you can reach the BPF Registry
3. **Test Artifact Polling** - Confirm you can get artifact lists
4. **Test Artifact Download** - Verify binary download works
5. **Implement eBPF Loading** - Complete the agent processing pipeline

## ✅ Summary

**The backend is fully implemented and working correctly.** The issue is that your agent team was looking at the wrong service (Actions API instead of BPF Registry). Once you update your agent configuration to point to the correct service (port 8090), the complete artifact processing pipeline should work immediately.

The BPF Registry has all the storage, APIs, and functionality needed for artifact management and distribution. No additional backend development is required.
