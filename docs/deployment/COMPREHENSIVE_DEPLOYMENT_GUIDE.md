# 🚀 Comprehensive Deployment Guide

This document consolidates all deployment guides, checklists, and deployment-related documentation for the Aegis Agent.

---

## 🎯 **Supported Platforms**

### **✅ Tested Distributions**
- **Ubuntu 20.04+ ARM64** (Recommended)
- **Debian 11+ ARM64** 
- **CentOS Stream 9 ARM64**
- **Rocky Linux 9 ARM64**
- **Amazon Linux 2 ARM64** (Graviton instances)
- **macOS ARM64** (Development)

### **🔧 Requirements**

#### **Hardware Requirements**
- **Architecture**: ARM64/AArch64 (64-bit ARM) or AMD64
- **Memory**: Minimum 1GB RAM, Recommended 2GB+
- **Storage**: 500MB free space for agent and eBPF programs
- **Network**: Internet connectivity for backend registration

#### **Software Requirements**
- **Kernel**: Linux 4.18+ with eBPF support
- **BTF**: Kernel BTF (BPF Type Format) support
- **Capabilities**: CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_BPF
- **Tools**: clang, llvm, bpftool, jq

---

## 🚀 **Quick Start Deployment**

### **1. Build the Agent**
```bash
cd agents/aegis
make build-linux-arm64  # For ARM64 Linux
make build-linux-amd64  # For AMD64 Linux
make build-darwin-arm64 # For macOS ARM64
```

### **2. Deploy as Systemd Service**
```bash
# Copy binary to system location
sudo cp aegis-agent-linux /usr/local/bin/aegis-agent
sudo chmod +x /usr/local/bin/aegis-agent

# Create systemd service
sudo cp docs/deployment/systemd/aegis.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable aegis-agent
sudo systemctl start aegis-agent
```

### **3. Verify Deployment**
```bash
# Check service status
sudo systemctl status aegis-agent

# Check logs
journalctl -u aegis-agent -f

# Check agent health
curl http://localhost:7070/health
```

---

## 📋 **Deployment Checklists**

### **Cap 5.B Checklist**
Generated: 2025-09-18T12:01:38.178263Z

- [ ] Signature verification (fails closed)
- [ ] Capability probe + publish
- [ ] CPU guard + auto-rollback
- [ ] /status exposes cpu_pct, loaded, capabilities
- [ ] Segmentation loaders (cgroup/TC) implemented
- [ ] Atomic map updates + counters readout

### **CAP5 Segmentation Checklist**
- [ ] eBPF templates for egress (cgroup connect)
- [ ] eBPF templates for ingress (tc classifier)
- [ ] Agent capability probe and loaders
- [ ] Cursor prompts for step-by-step implementation
- [ ] Segmentation work tracking

### **Agent CAP5B Checklist**
- [ ] Agent registration and authentication
- [ ] WebSocket communication established
- [ ] Module management system active
- [ ] eBPF program loading capability
- [ ] Policy enforcement ready
- [ ] Telemetry and monitoring active

---

## 🏗️ **Detailed Deployment Process**

### **Linux ARM64 Deployment**

#### **Prerequisites Setup**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required tools
sudo apt install -y clang llvm bpftool jq curl

# Verify eBPF support
sudo bpftool version
```

#### **Agent Installation**
```bash
# Create agent user (optional, for security)
sudo useradd -r -s /bin/false aegis-agent

# Create data directory
sudo mkdir -p /var/lib/aegis
sudo chown aegis-agent:aegis-agent /var/lib/aegis

# Install binary
sudo cp aegis-agent-linux /usr/local/bin/aegis-agent
sudo chmod +x /usr/local/bin/aegis-agent
```

#### **Systemd Service Configuration**
```ini
[Unit]
Description=Aegis Security Agent
Documentation=https://github.com/sgerhart/aegis_agent
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/aegis-agent --agent-id "aegis-linux-service" --backend-url "ws://192.168.1.157:8080/ws/agent" --log-level info
Restart=always
RestartSec=5
Environment=AEGIS_DATA_DIR=/var/lib/aegis
Environment=GOMAXPROCS=2

# Security settings
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/aegis /tmp
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF CAP_DAC_OVERRIDE

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

#### **Service Management**
```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable aegis-agent
sudo systemctl start aegis-agent

# Check status
sudo systemctl status aegis-agent

# View logs
journalctl -u aegis-agent -f

# Restart service
sudo systemctl restart aegis-agent

# Stop service
sudo systemctl stop aegis-agent
```

### **macOS Development Deployment**

#### **Prerequisites**
```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required tools
brew install go clang llvm jq

# Note: eBPF support limited on macOS
```

#### **Development Setup**
```bash
# Build for macOS
make build-darwin-arm64

# Run locally for testing
./aegis-agent-darwin --agent-id "aegis-mac-dev" --backend-url "ws://192.168.1.157:8080/ws/agent" --log-level debug
```

---

## 🔧 **Configuration Management**

### **Environment Variables**
```bash
# Required
AEGIS_DATA_DIR=/var/lib/aegis          # Data directory
AGENT_ID=aegis-linux-service           # Agent identifier
BACKEND_URL=ws://192.168.1.157:8080/ws/agent  # Backend WebSocket URL

# Optional
LOG_LEVEL=info                         # Log level (debug, info, warn, error)
HTTP_PORT=7070                         # HTTP status server port
HEARTBEAT_INTERVAL=60s                 # Heartbeat interval
RECONNECT_INTERVAL=5s                  # Reconnection interval
```

### **Configuration File**
```yaml
# /etc/aegis/agent.yaml
agent:
  id: "aegis-linux-service"
  data_dir: "/var/lib/aegis"
  log_level: "info"

backend:
  url: "ws://192.168.1.157:8080/ws/agent"
  reconnect_interval: "5s"
  heartbeat_interval: "60s"

modules:
  telemetry:
    enabled: true
    interval: "30s"
  websocket_communication:
    enabled: true
  observability:
    enabled: true
  analysis:
    enabled: false
  threat_intelligence:
    enabled: false
  advanced_policy:
    enabled: false

security:
  key_size: 256
  encryption: "chacha20-poly1305"
  signature: "ed25519"
```

---

## 🛠️ **Troubleshooting Deployment**

### **Common Issues**

#### **1. Permission Denied for eBPF**
```
ERROR: failed to load eBPF program: operation not permitted
```

**Solution**:
```bash
# Ensure proper capabilities
sudo setcap cap_sys_admin,cap_net_admin,cap_bpf+ep /usr/local/bin/aegis-agent

# Or run as root with proper capabilities in systemd service
```

#### **2. Data Directory Permission Issues**
```
ERROR: failed to create data directory: permission denied
```

**Solution**:
```bash
# Create and set proper permissions
sudo mkdir -p /var/lib/aegis
sudo chown root:root /var/lib/aegis
sudo chmod 755 /var/lib/aegis
```

#### **3. WebSocket Connection Failed**
```
ERROR: failed to connect to backend: dial tcp 192.168.1.157:8080: connect: connection refused
```

**Solution**:
- Check backend is running
- Verify network connectivity
- Check firewall rules
- Verify WebSocket URL format

#### **4. Agent Registration Failed**
```
ERROR: registration failed: signature verification failed
```

**Solution**:
- Check agent ID matches backend expectations
- Verify Ed25519 key generation
- Check signature calculation
- Review backend logs for specific errors

### **Debug Commands**
```bash
# Check agent process
ps aux | grep aegis-agent

# Check systemd service
sudo systemctl status aegis-agent

# View detailed logs
journalctl -u aegis-agent --no-pager -l

# Check network connectivity
curl -v http://192.168.1.157:8080/healthz

# Test WebSocket connection
wscat -c ws://192.168.1.157:8080/ws/agent
```

---

## 📊 **Monitoring & Health Checks**

### **Health Check Endpoint**
```bash
# Check agent health
curl http://localhost:7070/health

# Response
{
  "status": "healthy",
  "timestamp": "2025-09-27T02:43:19Z",
  "uptime": "1h23m45s",
  "modules": {
    "telemetry": "running",
    "websocket_communication": "running",
    "observability": "running"
  },
  "backend_connection": "connected",
  "last_heartbeat": "2025-09-27T02:43:19Z"
}
```

### **Log Monitoring**
```bash
# Real-time log monitoring
journalctl -u aegis-agent -f

# Log filtering
journalctl -u aegis-agent --since "1 hour ago" | grep ERROR

# Log rotation setup
sudo logrotate -d /etc/logrotate.d/aegis-agent
```

### **Performance Monitoring**
```bash
# Resource usage
top -p $(pgrep aegis-agent)

# Memory usage
pmap $(pgrep aegis-agent)

# Network connections
netstat -tulpn | grep aegis-agent
```

---

## 🔒 **Security Considerations**

### **Capabilities Required**
- **CAP_SYS_ADMIN**: For eBPF program loading
- **CAP_NET_ADMIN**: For network policy enforcement
- **CAP_BPF**: For BPF operations
- **CAP_DAC_OVERRIDE**: For file system access

### **Security Best Practices**
1. **Run as non-root user** when possible (requires capability delegation)
2. **Restrict file system access** using systemd security options
3. **Enable audit logging** for security events
4. **Regular security updates** for the host system
5. **Network segmentation** for backend communication

### **Audit Configuration**
```bash
# Enable audit logging
sudo auditctl -w /usr/local/bin/aegis-agent -p x -k aegis_agent
sudo auditctl -w /var/lib/aegis -p rwxa -k aegis_data
```

---

## 🚀 **Next Steps**

### **Post-Deployment Tasks**
1. **Verify agent registration** in backend dashboard
2. **Test module control** functionality
3. **Configure monitoring** and alerting
4. **Set up log aggregation** and analysis
5. **Implement backup** and recovery procedures

### **Maintenance Tasks**
1. **Regular log rotation** and cleanup
2. **Monitor resource usage** and performance
3. **Update agent** when new versions are available
4. **Review security** logs and events
5. **Test disaster recovery** procedures

### **Scaling Considerations**
1. **Load balancing** for multiple agents
2. **Centralized configuration** management
3. **Automated deployment** and updates
4. **Resource monitoring** and alerting
5. **Backup and disaster recovery** planning
