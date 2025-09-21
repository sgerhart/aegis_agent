#!/bin/bash

# New ARM64 Host Setup Script
# Run this on your NEW ARM64 Linux host during initial setup
# Usage: sudo ./new_host_setup.sh

set -e

echo "🚀 Setting up new ARM64 Linux host for Aegis Agent"
echo "Date: $(date)"
echo "Architecture: $(uname -m)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (sudo)"
   exit 1
fi

echo "=========================================="
echo "📋 1. SYSTEM PREPARATION"
echo "=========================================="

# Update system
echo "🔄 Updating system packages..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    # Install core packages first
    apt-get install -y curl wget jq git clang llvm build-essential linux-tools-generic
    
    # Try to install bpftool, with fallbacks
    echo "🔧 Installing bpftool..."
    if apt-get install -y bpftool 2>/dev/null; then
        echo "✅ bpftool installed from package"
    elif apt-get install -y linux-tools-$(uname -r) 2>/dev/null; then
        echo "✅ bpftool installed via linux-tools"
        # Create symlink if needed
        if [ -f /usr/lib/linux-tools/*/bpftool ]; then
            ln -sf /usr/lib/linux-tools/*/bpftool /usr/local/bin/bpftool
        fi
    else
        echo "⚠️  bpftool package not available, will build from source"
        # Install dependencies for building bpftool
        apt-get install -y libelf-dev zlib1g-dev
        # We'll build it later
        NEED_BUILD_BPFTOOL=1
    fi
    
elif command -v dnf >/dev/null 2>&1; then
    dnf update -y
    dnf install -y curl wget jq git clang llvm gcc make elfutils-libelf-devel zlib-devel
    # Try bpftool
    dnf install -y bpftool || NEED_BUILD_BPFTOOL=1
    
elif command -v yum >/dev/null 2>&1; then
    yum update -y
    yum install -y curl wget jq git clang llvm gcc make elfutils-libelf-devel zlib-devel
    # Try bpftool
    yum install -y bpftool || NEED_BUILD_BPFTOOL=1
    
else
    echo "❌ Unsupported package manager"
    exit 1
fi

# Build bpftool from source if needed
if [ "$NEED_BUILD_BPFTOOL" = "1" ]; then
    echo "🔨 Building bpftool from source..."
    cd /tmp
    
    # Get kernel version for source
    KERNEL_VERSION=$(uname -r | cut -d'-' -f1)
    
    # Try to get kernel source or use a known good version
    if wget -q https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.tar.xz; then
        tar -xf linux-6.1.tar.xz
        cd linux-6.1/tools/bpf/bpftool
    elif git clone --depth 1 https://github.com/libbpf/bpftool.git; then
        cd bpftool/src
    else
        echo "❌ Cannot download bpftool source"
        exit 1
    fi
    
    # Build bpftool
    make -j$(nproc) || make
    
    # Install
    cp bpftool /usr/local/bin/bpftool
    chmod +x /usr/local/bin/bpftool
    
    # Create symlink in standard location
    ln -sf /usr/local/bin/bpftool /usr/sbin/bpftool
    
    cd /
    rm -rf /tmp/linux-* /tmp/bpftool
    
    echo "✅ bpftool built and installed from source"
fi

echo "=========================================="
echo "📋 2. USER SETUP (steve)"
echo "=========================================="

# Create steve user if it doesn't exist
if ! id steve >/dev/null 2>&1; then
    echo "👤 Creating user steve..."
    useradd -m -s /bin/bash steve
    echo "steve:C!sco#123" | chpasswd
    usermod -aG sudo steve
else
    echo "✅ User steve already exists"
    # Update password
    echo "steve:C!sco#123" | chpasswd
fi

# Set up SSH for steve user
echo "🔑 Setting up SSH for steve..."
sudo -u steve mkdir -p /home/steve/.ssh
sudo -u steve chmod 700 /home/steve/.ssh

# Add the SSH public key
cat > /home/steve/.ssh/authorized_keys << 'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDB5iv2Pc01+cxcRj7lXyLzKp0BDyHdfJ3o93GB9YzhA5IOVG0oVDFL/GHgxet3bHYvTSKb3fm07NrVL4P4N/PYVsKFBUiU0L2UxQW1q3GbShOw7qAkoHHA3Y5BT4fAAFfVbHSUXxxZywAU053ry9B4qDBGqMd57NlS3csMyA3h9SjEtnGQKyqKzAWc+t9QjdrbF9Yb2ErI32nTsSBkRJxI2eeybmLdt58yK9+ZiedmNWkXHdjnY+GaYAFBWUG57TCk/MBB+ESy4wz6vqL2huwGD0lj1uk0FLbdald3XK73TYBXDKjrYRrUilht7W5zIt3yK177PJTplSvE8jML65as+qYD3T2lynd5cvCp/jRLVLn5bwaieK8FVTTHV0IPSWqeG0yOQJKaY9j6f1LIm1pHSnZfy5fKeBrQknODAEXh0CLKkLuULRrmEMUTigTTC5xi4Nz8iMZxDbjYjcv02AV2lJ0mV17CvoM3jeGdn1682TNSiWFHtgbJqlCHH3Nlxhg/oZoA4WwdhqQJganA18IdZuFd3xMrvHUKGWWsk+RMzeo0HlnzJg0TbH56xxpShz56G16XOF6dA9hKwhg6+GH+maPpw2Ish0VEHTFTuGvjX2m5H7zoRy0qAwyMzB7WrYpKyreMEdXa3HHEUPNr96oaVLQO3AsVnoRb4YhNIoYlkw== aegis-agent-deployment
EOF

# Set correct permissions
chmod 600 /home/steve/.ssh/authorized_keys
chown -R steve:steve /home/steve/.ssh
chmod 755 /home/steve

echo "=========================================="
echo "📋 3. SSH CONFIGURATION"
echo "=========================================="

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

# Configure SSH properly
cat > /etc/ssh/sshd_config << 'EOF'
# SSH Configuration for ARM64 Aegis Host
Port 22
AddressFamily any
ListenAddress 0.0.0.0

# Host Keys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication
LoginGraceTime 2m
PermitRootLogin yes
StrictModes yes
MaxAuthTries 6
MaxSessions 10

# Public Key Authentication
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Password Authentication (fallback)
PasswordAuthentication yes
PermitEmptyPasswords no

# Other authentication
KbdInteractiveAuthentication no
UsePAM yes

# Connection settings
X11Forwarding yes
PrintMotd no
TCPKeepAlive yes
UseDNS no

# Security
PermitTunnel no
GatewayPorts no

# Allow users
AllowUsers steve root

# SFTP subsystem
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

# Test and restart SSH
sshd -t
systemctl restart ssh
systemctl enable ssh

echo "=========================================="
echo "📋 4. AEGIS AGENT PREPARATION"
echo "=========================================="

# Create Aegis directories
mkdir -p /opt/aegis/{bin,config,logs,policies,bpf}
mkdir -p /etc/aegis

# Create configuration
cat > /opt/aegis/config/aegis.env << EOF
# Aegis Agent Configuration for ARM64
AGENT_HOST_ID=$(hostname)-arm64-$(date +%s)
AGENT_ID=aegis-$(hostname)-arm64
ORG_ID=default

# Backend URLs (update these as needed)
ACTIONS_API_URL=http://localhost:8083
AGENT_REGISTRY_URL=http://localhost:8090
NATS_URL=nats://localhost:4222

# Agent Configuration
AGENT_HTTP_ADDR=:7070
AEGIS_VERBOSE=true
AEGIS_DRY_RUN=false
AEGIS_MTLS=false
AEGIS_REGISTER=true

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

# Create systemd service template
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

# Security settings for eBPF
NoNewPrivileges=false
PrivateDevices=false
ProtectSystem=false
ProtectHome=false

# Required capabilities for eBPF
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
chown -R root:root /opt/aegis
chmod -R 755 /opt/aegis
chmod 600 /opt/aegis/config/aegis.env

echo "=========================================="
echo "📋 5. SYSTEM VERIFICATION"
echo "=========================================="

# Check eBPF support
echo "🔍 Checking eBPF support..."
ls -la /sys/kernel/btf/vmlinux && echo "✅ BTF available" || echo "❌ BTF not available"
mount | grep bpf && echo "✅ BPF filesystem mounted" || echo "❌ BPF filesystem not mounted"

# Check tools
echo "🔧 Checking required tools..."
which clang && echo "✅ clang available" || echo "❌ clang missing"
which bpftool && echo "✅ bpftool available" || echo "❌ bpftool missing"
which jq && echo "✅ jq available" || echo "❌ jq missing"

# Check network
echo "🌐 Checking network..."
ping -c 2 8.8.8.8 >/dev/null 2>&1 && echo "✅ Internet connectivity" || echo "❌ No internet"

echo "=========================================="
echo "📋 6. SUMMARY"
echo "=========================================="

echo "✅ New ARM64 host setup complete!"
echo ""
echo "📊 System Information:"
echo "   Hostname: $(hostname)"
echo "   IP Address: $(hostname -I | awk '{print $1}')"
echo "   Architecture: $(uname -m)"
echo "   OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
echo "   Kernel: $(uname -r)"
echo ""
echo "👤 User Configuration:"
echo "   User: steve"
echo "   Password: C!sco#123"
echo "   SSH Key: ✅ Configured"
echo "   Sudo: ✅ Enabled"
echo ""
echo "🔧 Next Steps:"
echo "   1. Test SSH: ssh steve@$(hostname -I | awk '{print $1}')"
echo "   2. Deploy agent binary to: /opt/aegis/bin/aegis"
echo "   3. Start agent: sudo systemctl enable --now aegis"
echo "   4. Monitor: sudo journalctl -u aegis -f"
echo ""
echo "📋 Agent Configuration:"
echo "   Config: /opt/aegis/config/aegis.env"
echo "   Service: /etc/systemd/system/aegis.service"
echo "   Logs: journalctl -u aegis"
echo "   Health: curl http://localhost:7070/healthz"
echo ""
echo "🔑 SSH Test Command (from Mac):"
echo "   ssh -i ~/.ssh/aegis_agent_key steve@$(hostname -I | awk '{print $1}')"
