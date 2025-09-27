# 📦 Aegis Agent - Installation Guide

## System Requirements

### **Minimum Requirements**
- **OS**: Linux (Ubuntu 18.04+, CentOS 7+, RHEL 7+)
- **Architecture**: x86_64 or ARM64
- **RAM**: 512MB minimum, 1GB recommended
- **CPU**: 1 core minimum, 2 cores recommended
- **Disk**: 100MB for agent binary and logs

### **Network Requirements**
- **Outbound HTTPS**: Port 443 (for backend communication)
- **Outbound WebSocket**: Port 8080 (for real-time communication)
- **Inbound**: No inbound ports required (agent initiates all connections)

## 🚀 Installation Methods

### **Method 1: Systemd Service (Recommended)**

#### **Step 1: Download Agent Binary**
```bash
# Download the latest agent binary
sudo wget https://releases.aegis.com/agent/latest/aegis-agent-linux-amd64 -O /usr/local/bin/aegis-agent

# Make it executable
sudo chmod +x /usr/local/bin/aegis-agent
```

#### **Step 2: Create System User**
```bash
# Create dedicated user for agent
sudo useradd -r -s /bin/false -d /var/lib/aegis aegis

# Create data directory
sudo mkdir -p /var/lib/aegis
sudo chown aegis:aegis /var/lib/aegis
```

#### **Step 3: Create Systemd Service**
```bash
# Create service file
sudo tee /etc/systemd/system/aegis-agent.service > /dev/null <<EOF
[Unit]
Description=Aegis Security Agent
Documentation=https://docs.aegis.com
After=network.target
Wants=network.target

[Service]
Type=simple
User=aegis
Group=aegis
ExecStart=/usr/local/bin/aegis-agent --agent-id aegis-linux-service --backend-url ws://192.168.1.157:8080/ws/agent --log-level info
Restart=always
RestartSec=5
Environment=AEGIS_DATA_DIR=/var/lib/aegis

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/aegis
ReadWritePaths=/sys/fs/bpf
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF

[Install]
WantedBy=multi-user.target
EOF
```

#### **Step 4: Start the Service**
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable aegis-agent

# Start the service
sudo systemctl start aegis-agent

# Check status
sudo systemctl status aegis-agent
```

### **Method 2: Docker Container**

#### **Step 1: Create Docker Compose File**
```yaml
version: '3.8'
services:
  aegis-agent:
    image: aegis/agent:latest
    container_name: aegis-agent
    restart: unless-stopped
    privileged: true
    environment:
      - AEGIS_DATA_DIR=/var/lib/aegis
      - BACKEND_URL=ws://192.168.1.157:8080/ws/agent
      - AGENT_ID=aegis-docker
      - LOG_LEVEL=info
    volumes:
      - /var/lib/aegis:/var/lib/aegis
      - /sys/fs/bpf:/sys/fs/bpf
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
      - BPF
```

#### **Step 2: Run with Docker Compose**
```bash
# Start the container
docker-compose up -d

# Check logs
docker-compose logs -f aegis-agent
```

### **Method 3: Manual Installation**

#### **Step 1: Download and Extract**
```bash
# Download agent
wget https://releases.aegis.com/agent/latest/aegis-agent-linux-amd64.tar.gz

# Extract
tar -xzf aegis-agent-linux-amd64.tar.gz

# Move to system location
sudo mv aegis-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/aegis-agent
```

#### **Step 2: Create Configuration**
```bash
# Create config directory
sudo mkdir -p /etc/aegis

# Create configuration file
sudo tee /etc/aegis/agent.conf > /dev/null <<EOF
{
  "agent_id": "aegis-manual",
  "backend_url": "ws://192.168.1.157:8080/ws/agent",
  "log_level": "info",
  "data_dir": "/var/lib/aegis"
}
EOF
```

#### **Step 3: Run Manually**
```bash
# Create data directory
sudo mkdir -p /var/lib/aegis

# Run agent (use screen/tmux for background)
screen -S aegis-agent
sudo /usr/local/bin/aegis-agent --config /etc/aegis/agent.conf
# Press Ctrl+A, then D to detach
```

## 🔧 Configuration Options

### **Command Line Arguments**
```bash
aegis-agent [OPTIONS]

Options:
  --agent-id string        Agent identifier (default: "aegis-agent")
  --backend-url string     Backend WebSocket URL (required)
  --log-level string       Log level: debug, info, warn, error (default: "info")
  --data-dir string        Data directory (default: "/var/lib/aegis")
  --config string          Configuration file path
  --version               Show version information
```

### **Environment Variables**
```bash
# Core settings
export AEGIS_AGENT_ID="aegis-custom"
export AEGIS_BACKEND_URL="ws://192.168.1.157:8080/ws/agent"
export AEGIS_LOG_LEVEL="info"
export AEGIS_DATA_DIR="/var/lib/aegis"

# Advanced settings
export GOMAXPROCS="2"              # Limit CPU usage
export AEGIS_HEARTBEAT_INTERVAL="60s"  # Heartbeat frequency
export AEGIS_RECONNECT_DELAY="5s"      # Reconnection delay
```

## ✅ Post-Installation Verification

### **1. Check Service Status**
```bash
# Verify service is running
sudo systemctl is-active aegis-agent

# Check detailed status
sudo systemctl status aegis-agent
```

### **2. Verify Connection**
```bash
# Check logs for successful connection
sudo journalctl -u aegis-agent | grep "Connected to backend"

# Should see something like:
# [websocket] Connected to backend at ws://192.168.1.157:8080/ws/agent
```

### **3. Test Functionality**
```bash
# Check enforcement cycles
sudo journalctl -u aegis-agent | grep "Enforcement cycle completed"

# Should see periodic messages like:
# [enforcer] Enforcement cycle completed (maps: 3)
```

### **4. Monitor for Issues**
```bash
# Watch logs in real-time
sudo journalctl -u aegis-agent -f

# Check for errors
sudo journalctl -u aegis-agent | grep -E "(ERROR|Failed|failed)"
```

## 🔄 Updates and Maintenance

### **Updating the Agent**
```bash
# Stop the service
sudo systemctl stop aegis-agent

# Download new version
sudo wget https://releases.aegis.com/agent/latest/aegis-agent-linux-amd64 -O /usr/local/bin/aegis-agent.new

# Replace binary
sudo mv /usr/local/bin/aegis-agent.new /usr/local/bin/aegis-agent
sudo chmod +x /usr/local/bin/aegis-agent

# Restart service
sudo systemctl start aegis-agent
```

### **Uninstalling**
```bash
# Stop and disable service
sudo systemctl stop aegis-agent
sudo systemctl disable aegis-agent

# Remove service file
sudo rm /etc/systemd/system/aegis-agent.service

# Remove binary
sudo rm /usr/local/bin/aegis-agent

# Remove data (optional - this will delete agent identity)
sudo rm -rf /var/lib/aegis

# Reload systemd
sudo systemctl daemon-reload
```

## 🆘 Troubleshooting Installation

### **Permission Denied**
```bash
# Fix ownership
sudo chown -R aegis:aegis /var/lib/aegis
sudo chmod 755 /var/lib/aegis
```

### **Port Already in Use**
```bash
# Find process using port 7070
sudo lsof -i :7070

# Kill conflicting process or change agent port
```

### **Service Won't Start**
```bash
# Check service configuration
sudo systemctl cat aegis-agent

# Test binary manually
sudo /usr/local/bin/aegis-agent --version
```

---

**🎯 Installation Complete!** Your system is now protected by Aegis Agent. Check the [Quick Start Guide](QUICK_START_GUIDE.md) to verify everything is working correctly.
