#!/bin/bash

# Deploy Aegis Agent to Linux ARM64 Host
# Usage: ./deploy_to_arm.sh [user@host] [path]

set -e

USER_HOST=${1:-"user@arm-host"}
REMOTE_PATH=${2:-"/opt/aegis"}

echo "🚀 Deploying Aegis Agent to Linux ARM64 Host: $USER_HOST"

# Detect remote architecture
echo "🔍 Detecting remote architecture..."
REMOTE_ARCH=$(ssh $USER_HOST "uname -m")
echo "Remote architecture: $REMOTE_ARCH"

# Select appropriate binary
if [[ "$REMOTE_ARCH" == "aarch64" || "$REMOTE_ARCH" == "arm64" ]]; then
    BINARY="agents/aegis/aegis-linux-arm64"
    echo "✅ Using ARM64 binary"
elif [[ "$REMOTE_ARCH" == "x86_64" ]]; then
    BINARY="agents/aegis/aegis-linux-amd64"
    echo "✅ Using AMD64 binary"
else
    echo "❌ Unsupported architecture: $REMOTE_ARCH"
    exit 1
fi

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "❌ Binary not found: $BINARY"
    echo "💡 Run: cd agents/aegis && GOOS=linux GOARCH=arm64 go build -o aegis-linux-arm64 cmd/aegis/main_ubuntu_simple_integrated.go"
    exit 1
fi

# Detect remote OS
echo "🔍 Detecting remote OS..."
REMOTE_OS=$(ssh $USER_HOST "cat /etc/os-release | grep '^ID=' | cut -d'=' -f2 | tr -d '\"'")
echo "Remote OS: $REMOTE_OS"

# Create remote directory
echo "📁 Creating remote directory: $REMOTE_PATH"
ssh $USER_HOST "sudo mkdir -p $REMOTE_PATH/bin $REMOTE_PATH/config $REMOTE_PATH/logs $REMOTE_PATH/policies"

# Copy binary
echo "📦 Copying aegis binary for $REMOTE_ARCH..."
scp $BINARY $USER_HOST:/tmp/aegis
ssh $USER_HOST "sudo mv /tmp/aegis $REMOTE_PATH/bin/aegis && sudo chmod +x $REMOTE_PATH/bin/aegis"

# Verify binary works on target
echo "🧪 Testing binary on target..."
ssh $USER_HOST "sudo $REMOTE_PATH/bin/aegis --help | head -5"

# Install dependencies based on OS
echo "🔧 Installing dependencies for $REMOTE_OS..."
case $REMOTE_OS in
    "ubuntu"|"debian")
        ssh $USER_HOST "sudo apt-get update && sudo apt-get install -y clang llvm bpftool jq curl"
        ;;
    "centos"|"rhel"|"rocky"|"almalinux")
        ssh $USER_HOST "sudo yum install -y clang llvm bpftool jq curl || sudo dnf install -y clang llvm bpftool jq curl"
        ;;
    "alpine")
        ssh $USER_HOST "sudo apk add --no-cache clang llvm bpftool jq curl"
        ;;
    *)
        echo "⚠️  Unknown OS: $REMOTE_OS. Please install clang, llvm, bpftool, jq, curl manually"
        ;;
esac

# Copy systemd service
echo "🔧 Installing systemd service..."
scp agents/aegis/systemd/aegis.service $USER_HOST:/tmp/aegis.service
ssh $USER_HOST "sudo mv /tmp/aegis.service /etc/systemd/system/ && sudo systemctl daemon-reload"

# Copy configuration files
echo "⚙️  Copying configuration..."
if [ -d "agents/aegis/configs" ]; then
    scp -r agents/aegis/configs/* $USER_HOST:/tmp/configs/
    ssh $USER_HOST "sudo cp -r /tmp/configs/* $REMOTE_PATH/config/ && sudo rm -rf /tmp/configs"
fi

# Copy BPF programs and templates
echo "🔗 Copying eBPF programs..."
if [ -d "bpf" ]; then
    scp -r bpf $USER_HOST:/tmp/
    ssh $USER_HOST "sudo mv /tmp/bpf $REMOTE_PATH/ && sudo chown -R root:root $REMOTE_PATH/bpf"
fi

# Copy sample policies
echo "📋 Copying sample policies..."
if [ -d "policies" ]; then
    scp -r policies/* $USER_HOST:/tmp/policies/
    ssh $USER_HOST "sudo cp -r /tmp/policies/* $REMOTE_PATH/policies/ && sudo rm -rf /tmp/policies"
fi

# Set permissions
echo "🔐 Setting permissions..."
ssh $USER_HOST "sudo chown -R root:root $REMOTE_PATH && sudo chmod -R 755 $REMOTE_PATH"

# Create ARM-optimized environment file
echo "📝 Creating ARM-optimized environment configuration..."
cat > /tmp/aegis.env << EOF
# Aegis Agent Configuration for ARM64
AGENT_HOST_ID=\$(hostname)-arm64
AGENT_ID=aegis-\$(hostname)-arm64-\$(date +%s)
ORG_ID=default

# Backend URLs
ACTIONS_API_URL=http://localhost:8083
AGENT_REGISTRY_URL=http://localhost:8090
NATS_URL=nats://localhost:4222

# Agent Configuration
AGENT_HTTP_ADDR=:7070
AEGIS_VERBOSE=true
AEGIS_DRY_RUN=false
AEGIS_MTLS=false

# eBPF Configuration
AEGIS_EBPF=true
AEGIS_SEGMENTATION=true

# ARM64 Optimizations
CLANG_PATH=/usr/bin/clang
BPFTOOL_PATH=/usr/sbin/bpftool
BTF_PATH=/sys/kernel/btf/vmlinux
BUILD_OUTPUT_DIR=$REMOTE_PATH/bpf/build

# Performance tuning for ARM
GOMAXPROCS=0
GOGC=100
EOF

scp /tmp/aegis.env $USER_HOST:/tmp/
ssh $USER_HOST "sudo mv /tmp/aegis.env $REMOTE_PATH/config/aegis.env"

# Create ARM-specific startup script
echo "📝 Creating ARM-specific startup script..."
cat > /tmp/start-aegis-arm.sh << 'EOF'
#!/bin/bash
# ARM64-optimized Aegis startup script

set -e

AEGIS_PATH="/opt/aegis"
CONFIG_FILE="$AEGIS_PATH/config/aegis.env"

# Source configuration
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# Check ARM64 capabilities
echo "🔍 ARM64 System Check:"
echo "Architecture: $(uname -m)"
echo "Kernel: $(uname -r)"
echo "CPU: $(lscpu | grep 'Model name' | cut -d':' -f2 | xargs)"
echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2}')"

# Check eBPF support
echo "📋 eBPF Support Check:"
ls -la /sys/kernel/btf/vmlinux 2>/dev/null && echo "✅ BTF available" || echo "❌ BTF not available"
which clang >/dev/null 2>&1 && echo "✅ clang available" || echo "❌ clang missing"
which bpftool >/dev/null 2>&1 && echo "✅ bpftool available" || echo "❌ bpftool missing"

# Start agent
echo "🚀 Starting Aegis Agent on ARM64..."
exec "$AEGIS_PATH/bin/aegis" "$@"
EOF

scp /tmp/start-aegis-arm.sh $USER_HOST:/tmp/
ssh $USER_HOST "sudo mv /tmp/start-aegis-arm.sh $REMOTE_PATH/bin/start-aegis && sudo chmod +x $REMOTE_PATH/bin/start-aegis"

# System capability check
echo "🔍 ARM64 System Capability Check..."
ssh $USER_HOST "
echo '=== ARM64 System Information ==='
echo 'Architecture:' \$(uname -m)
echo 'Kernel:' \$(uname -r)
echo 'OS:' \$(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')
echo 'CPU Info:'
lscpu | grep -E 'Architecture|CPU|Model|Thread|Core' | head -5
echo 'Memory:'
free -h
echo 'eBPF Support:'
ls -la /sys/kernel/btf/vmlinux 2>/dev/null || echo 'BTF not found'
echo 'Required tools:'
which clang && clang --version | head -1 || echo 'clang not found'
which bpftool && bpftool version || echo 'bpftool not found'
echo '=== End System Info ==='
"

echo "✅ ARM64 deployment complete!"
echo ""
echo "🔧 Next steps on the ARM64 Linux host:"
echo "   1. Configure environment: sudo nano $REMOTE_PATH/config/aegis.env"
echo "   2. Test the agent: sudo $REMOTE_PATH/bin/aegis --help"
echo "   3. Quick test: sudo $REMOTE_PATH/bin/start-aegis --dry-run --verbose"
echo "   4. Start the service: sudo systemctl enable --now aegis"
echo "   5. Check status: sudo systemctl status aegis"
echo "   6. View logs: sudo journalctl -u aegis -f"
echo ""
echo "🌐 Agent endpoints (once running):"
echo "   - Health: http://[arm-host]:7070/healthz"
echo "   - Status: http://[arm-host]:7070/status"
echo "   - Policies: http://[arm-host]:7070/policies"
echo ""
echo "📊 ARM64 specific features:"
echo "   - Optimized binary size: $(du -h $BINARY | cut -f1)"
echo "   - ARM64 performance tuning enabled"
echo "   - Architecture-specific configuration"
