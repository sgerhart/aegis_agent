# Agent Artifact Processing Guide

## Overview

This document explains how the AegisFlux agent processes artifacts received from the BPF Registry, including the structure of artifacts and the complete deployment flow.

## Artifact Structure

### What is an Artifact?

An artifact is a **complete eBPF policy package** that contains:
1. **Metadata (JSON)** - Policy configuration and catalog information
2. **eBPF Program (Binary)** - Compiled kernel-level enforcement code
3. **Signature** - Vault-signed for cryptographic verification
4. **Parameters** - Runtime configuration (IP addresses, protocols, etc.)

### Example: ICMP Block Policy for 8.8.8.8

When creating an artifact to block ICMP traffic to 8.8.8.8, here's the complete structure:

#### 1. Metadata (JSON)
```json
{
  "name": "block-icmp-8888",
  "version": "1.0.0",
  "description": "Block ICMP ping traffic to 8.8.8.8",
  "type": "program",
  "architecture": "arm64",
  "kernel_version": "5.4.0",
  "metadata": {
    "policy_type": "network_block",
    "protocol": "icmp",
    "target_ip": "8.8.8.8",
    "direction": "egress",
    "action": "drop",
    "hook": "tc_egress"
  },
  "tags": ["network", "security", "icmp", "blocking", "egress"],
  "signature": "gCx+xz/3OoEIEFJlCx3XczSqgKA1TMp78D9drp8QA5I=",
  "size": 1024,
  "checksum": "0c20d1bc67e6097920f228cbbbdd5a7258f6cf51efd953bc524f39955dfb698a"
}
```

#### 2. eBPF Program (C Code Example)
```c
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/icmp.h>

SEC("tc")
int block_icmp_egress(struct __sk_buff *skb) {
    // Parse packet headers
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct iphdr *iph = data;
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_OK;
    
    // Check if ICMP packet
    if (iph->protocol != IPPROTO_ICMP)
        return TC_ACT_OK;
    
    // Check destination IP (8.8.8.8 = 0x08080808)
    if (iph->daddr != 0x08080808)
        return TC_ACT_OK;
    
    // Block this ICMP packet
    bpf_printk("Blocking ICMP to 8.8.8.8");
    return TC_ACT_SHOT;  // Drop packet
}

char _license[] SEC("license") = "GPL";
```

#### 3. Compiled Artifact (tar.zst)
```
artifact_123.tar.zst
├── metadata.json          # Runtime parameters
├── program.o              # Compiled eBPF bytecode
├── config.json            # Additional configuration
└── signature.bin          # Cryptographic signature
```

## Ingress vs Egress Rules

### For ICMP Blocking to 8.8.8.8:

**📤 EGRESS RULE (Recommended):**
- **Blocks:** Agent → 8.8.8.8 (outbound ping)
- **Hook:** `tc_egress` (outgoing traffic)
- **Use case:** Prevent agent from reaching external IP
- **Result:** `ping 8.8.8.8` fails from the agent

**📥 INGRESS RULE (Alternative):**
- **Blocks:** 8.8.8.8 → Agent (inbound ping)
- **Hook:** `tc_ingress` (incoming traffic)
- **Use case:** Block external IP from reaching agent
- **Result:** `ping 8.8.8.8` fails from external systems

## Agent Processing Flow

### Step 1: Polling for Assignments (Every 30 seconds)

```http
GET /artifacts/for-host/{host_id}
```

**Response:**
```json
{
  "artifacts": [
    {
      "id": "artifact_1758337790805007876",
      "name": "block-icmp-8888",
      "version": "1.0.0",
      "description": "Block ICMP ping traffic to 8.8.8.8",
      "signature": "gCx+xz/3OoEIEFJlCx3XczSqgKA1TMp78D9drp8QA5I=",
      "size": 1024,
      "metadata": {
        "policy_type": "network_block",
        "target_ip": "8.8.8.8",
        "protocol": "icmp",
        "direction": "egress"
      }
    }
  ],
  "total": 1
}
```

### Step 2: Metadata Processing

The agent processes the JSON metadata to:

1. **📝 Parse Policy Info** - Extract target IP, protocol, action
2. **🔍 Check if Already Loaded** - Skip if program already running
3. **📏 Validate Size** - Ensure artifact size is reasonable
4. **🔑 Verify Signature** - Check signature field exists
5. **💾 Plan Download** - Queue artifact for binary download

**Key Point:** The JSON metadata serves as a **CATALOG** - it tells the agent what artifacts are available for download, but the JSON itself is NOT the policy.

### Step 3: Binary Artifact Download

```http
GET /artifacts/{artifact_id}/binary
```

This downloads the actual `tar.zst` file containing:
- **📄 eBPF program** (compiled bytecode)
- **⚙️ Configuration parameters**
- **📋 Additional metadata**
- **🔐 Signature for verification**

### Step 4: Binary Processing

After downloading the `tar.zst` file, the agent:

1. **🔐 Verifies Signature** - Uses Vault public key to verify authenticity
2. **📦 Extracts Contents** - Unpacks tar.zst to get eBPF program + config
3. **🔍 Validates Checksum** - Ensures file integrity matches metadata
4. **📝 Reads Parameters** - Extracts runtime config (IP, protocol, etc.)
5. **💾 Caches Artifact** - Saves to local cache for future use

### Step 5: eBPF Program Deployment

Finally, the agent deploys the policy:

1. **🔧 Loads eBPF Program** - Uses libbpf to load bytecode into kernel
2. **🎯 Applies Parameters** - Configures program with target IP (8.8.8.8)
3. **🔗 Attaches to Hook** - Connects to TC egress hook on network interface
4. **⚡ Starts Enforcement** - Program begins dropping ICMP packets
5. **📊 Reports Status** - Sends telemetry to NATS about successful deployment

## Agent Code Flow

Based on the actual agent implementation:

```go
// 1. Poll for artifacts
artifacts, err := registryClient.GetArtifactsForHost(ctx)

// 2. Process each artifact
for _, artifact := range artifacts {
    // Check if already loaded
    if _, exists := loadedPrograms[artifact.ArtifactID]; exists {
        continue
    }
    
    // Download binary artifact
    artifactData, err := registryClient.DownloadArtifact(ctx, artifact.ArtifactID)
    
    // Verify signature
    err := registryClient.VerifySignature(ctx, artifactData, artifact.Signature, publicKey)
    
    // Save to cache
    err := bpfLoader.SaveToCache(artifact.ArtifactID, artifactData)
    
    // Load BPF program
    program, err := bpfLoader.LoadProgram(artifact.ArtifactID, artifactData, artifact.Parameters, ttl)
    
    // Store loaded program
    loadedPrograms[artifact.ArtifactID] = program
}
```

## Deployment Process Summary

### Backend → Agent Flow

1. **📦 Artifact Creation**
   - eBPF C code compiled to bytecode
   - Packaged as tar.zst with metadata
   - Signed with Vault private key

2. **📡 Assignment**
   - Admin assigns artifact to specific host
   - Backend updates artifact metadata with host assignment

3. **🔄 Agent Polling**
   - Agent polls registry every 30 seconds
   - Receives JSON catalog of assigned artifacts

4. **📥 Agent Download**
   - Agent downloads binary artifact using artifact ID
   - Verifies signature with Vault public key

5. **⚡ Kernel Deployment**
   - Agent loads eBPF program into kernel
   - Attaches to appropriate network hook
   - Program starts enforcing policy immediately

### Result

- **ping 8.8.8.8** → No response (packet dropped at kernel level)
- **Other traffic** → Unaffected
- **Kernel-level enforcement** → No bypass possible

## API Endpoints

### Agent Polling
```http
GET /artifacts/for-host/{host_id}
```

### Binary Download
```http
GET /artifacts/{artifact_id}/binary
```

### Management (Admin)
```http
POST /assign/{artifact_id}/{host_id}     # Assign artifact to host
DELETE /unassign/{artifact_id}/{host_id} # Remove assignment
PUT /hosts/{artifact_id}                 # Bulk host management
```

## Key Concepts

1. **JSON Metadata = Catalog** - Not the actual policy
2. **Binary Artifact = Policy** - Contains the actual eBPF program
3. **Two-Phase Process** - Poll for metadata, then download binary
4. **Kernel-Level Enforcement** - eBPF runs directly in Linux kernel
5. **Cryptographic Verification** - All artifacts are Vault-signed
6. **Automatic Deployment** - Agent handles download, verification, and deployment

## Testing

To test the complete flow:

1. Create an artifact with ICMP blocking policy
2. Assign it to a host
3. Agent polls and receives metadata
4. Agent downloads binary artifact
5. Agent loads eBPF program into kernel
6. Test: `ping 8.8.8.8` should fail

The agent provides detailed logging at each step for troubleshooting and monitoring.
