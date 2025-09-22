#!/bin/bash

# Deploy New Aegis Agent Directly on Linux Host
# Copy this script to your Linux host and run it there
# Usage: sudo ./deploy_directly_on_host.sh

echo "🚀 Deploying New Integrated Aegis Agent on $(hostname)"
echo "Architecture: $(uname -m)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
echo "Date: $(date)"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (sudo)"
   exit 1
fi

# Stop current agent if running
echo "🛑 Stopping current agent..."
pkill -f aegis-agent || echo "No existing agent process found"
systemctl stop aegis 2>/dev/null || echo "No systemd service to stop"

echo ""
echo "📁 Creating directory structure..."
mkdir -p /opt/aegis/{bin,config,logs,policies,bpf}
mkdir -p /etc/aegis

echo ""
echo "📥 You'll need to copy the new agent binary to this host."
echo "From your Mac, run:"
echo "   scp agents/aegis/aegis-linux-arm64 steve@$(hostname -I | awk '{print $1}'):/tmp/"
echo ""
echo "Once copied, run this script again with the binary present."

# Check if binary is available
if [ -f "/tmp/aegis-linux-arm64" ]; then
    echo "✅ Found new agent binary in /tmp/"
    
    # Install the new binary
    echo "📦 Installing new agent binary..."
    cp /tmp/aegis-linux-arm64 /opt/aegis/bin/aegis
    chmod +x /opt/aegis/bin/aegis
    chown root:root /opt/aegis/bin/aegis
    
    # Verify binary
    echo "🔍 Verifying new binary..."
    file /opt/aegis/bin/aegis
    ls -la /opt/aegis/bin/aegis
    
    # Test binary
    echo "🧪 Testing new binary..."
    /opt/aegis/bin/aegis --help | head -10
    
elif [ -f "/tmp/aegis" ]; then
    echo "✅ Found agent binary in /tmp/"
    
    # Install the binary
    echo "📦 Installing agent binary..."
    cp /tmp/aegis /opt/aegis/bin/aegis
    chmod +x /opt/aegis/bin/aegis
    chown root:root /opt/aegis/bin/aegis
    
    # Verify binary
    echo "🔍 Verifying binary..."
    file /opt/aegis/bin/aegis
    ls -la /opt/aegis/bin/aegis
    
    # Test binary
    echo "🧪 Testing binary..."
    /opt/aegis/bin/aegis --help | head -10
    
else
    echo "⚠️  No agent binary found in /tmp/"
    echo "Please copy the binary first:"
    echo "   From Mac: scp agents/aegis/aegis-linux-arm64 steve@$(hostname -I | awk '{print $1}'):/tmp/"
    echo "   Then re-run this script"
    exit 1
fi

echo ""
echo "⚙️  Creating configuration..."

# Create environment configuration
cat > /opt/aegis/config/aegis.env << EOF
# Aegis Agent Configuration
AGENT_HOST_ID=$(hostname)-arm64-$(date +%s)
AGENT_ID=aegis-$(hostname)-arm64
ORG_ID=default

# Backend URLs (update these to match your setup)
ACTIONS_API_URL=http://localhost:8083
AGENT_REGISTRY_URL=http://localhost:8090
NATS_URL=nats://localhost:4222

# Agent Configuration
AGENT_HTTP_ADDR=:7070
AEGIS_VERBOSE=true
AEGIS_DRY_RUN=false
AEGIS_MTLS=false
AEGIS_REGISTER=false

# eBPF Configuration
AEGIS_EBPF=true
AEGIS_SEGMENTATION=true

# ARM64 Optimizations
CLANG_PATH=/usr/bin/clang
BPFTOOL_PATH=/usr/sbin/bpftool
BTF_PATH=/sys/kernel/btf/vmlinux
BUILD_OUTPUT_DIR=/opt/aegis/bpf/build

# Performance tuning for ARM
GOMAXPROCS=0
GOGC=100
EOF

# Create systemd service file
echo "🔧 Creating systemd service..."
cat > /etc/systemd/system/aegis.service << 'EOF'
[Unit]
Description=Aegis eBPF Agent
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/aegis/bin/aegis
EnvironmentFile=/opt/aegis/config/aegis.env
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=false
PrivateDevices=false
ProtectSystem=false
ProtectHome=false

# Required for eBPF
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Create sample policy
echo "📋 Creating sample ARM64 policy..."
cat > /opt/aegis/policies/arm64_test.json << 'EOF'
{
  "id": "arm64-test-policy",
  "name": "ARM64 Test Policy",
  "description": "Simple test policy for ARM64 validation",
  "type": "network",
  "priority": 100,
  "enabled": true,
  "rules": [
    {
      "id": "block-test",
      "action": "deny",
      "priority": 10,
      "conditions": [
        {"field": "dest_ip", "operator": "eq", "value": "1.1.1.1"},
        {"field": "protocol", "operator": "eq", "value": "tcp"}
      ],
      "metadata": {
        "description": "Block Cloudflare DNS for testing",
        "test": true
      }
    }
  ],
  "metadata": {
    "test": true,
    "architecture": "arm64"
  }
}
EOF

# Set permissions
chown -R root:root /opt/aegis
chmod -R 755 /opt/aegis
chmod 600 /opt/aegis/config/aegis.env

echo ""
echo "🧪 Testing new agent installation..."

# Test the agent
echo "Testing agent help:"
/opt/aegis/bin/aegis --help | head -5

echo ""
echo "Testing dry-run mode (5 seconds):"
timeout 5s /opt/aegis/bin/aegis --dry-run --verbose --register=false || echo "Dry-run test completed"

echo ""
echo "✅ Installation complete!"
echo ""
echo "🔧 Next steps:"
echo "1. Enable and start the service:"
echo "   sudo systemctl enable aegis"
echo "   sudo systemctl start aegis"
echo ""
echo "2. Check status:"
echo "   sudo systemctl status aegis"
echo ""
echo "3. View logs:"
echo "   sudo journalctl -u aegis -f"
echo ""
echo "4. Test HTTP endpoints:"
echo "   curl http://localhost:7070/healthz"
echo "   curl http://localhost:7070/status"
echo ""
echo "5. Test with policy:"
echo "   /opt/aegis/bin/aegis --policy=/opt/aegis/policies/arm64_test.json --dry-run"
echo ""
echo "📊 Agent info:"
echo "Binary: $(file /opt/aegis/bin/aegis | cut -d':' -f2)"
echo "Size: $(du -h /opt/aegis/bin/aegis | cut -f1)"
echo "Config: /opt/aegis/config/aegis.env"
echo "Logs: journalctl -u aegis"
