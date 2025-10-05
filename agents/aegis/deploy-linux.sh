#!/bin/bash

# Aegis Agent Linux Deployment Script
# This script builds and deploys the Aegis Agent on Linux

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                Aegis Agent Linux Deployment                  ║"
echo "║              Enterprise Security Agent                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
AGENT_ID="${AEGIS_AGENT_ID:-aegis-agent-001}"
BACKEND_HOST="${AEGIS_BACKEND_HOST:-192.168.1.166}"
BACKEND_PORT="${AEGIS_BACKEND_PORT:-8080}"
LOG_LEVEL="${AEGIS_LOG_LEVEL:-info}"
INSTALL_DIR="${AEGIS_INSTALL_DIR:-/opt/aegis}"
SERVICE_USER="${AEGIS_SERVICE_USER:-aegis}"
SERVICE_GROUP="${AEGIS_SERVICE_GROUP:-aegis}"

echo "Configuration:"
echo "  Agent ID: $AGENT_ID"
echo "  Backend: $BACKEND_HOST:$BACKEND_PORT"
echo "  Log Level: $LOG_LEVEL"
echo "  Install Dir: $INSTALL_DIR"
echo "  Service User: $SERVICE_USER"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root for system installation"
    echo "Usage: sudo ./deploy-linux.sh"
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go 1.21 or later."
    echo "Visit: https://golang.org/dl/"
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_VERSION="1.21"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Error: Go version $GO_VERSION is too old. Required: $REQUIRED_VERSION or later"
    exit 1
fi

echo "✓ Go version check passed: $GO_VERSION"
echo ""

# Build the agent
echo "Building Aegis Agent..."
cd "$(dirname "$0")"

# Set build flags for Linux
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=1

# Build with optimizations
go build -ldflags="-s -w -X main.version=1.0.1 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o aegis ./cmd/aegis

if [ $? -ne 0 ]; then
    echo "Error: Failed to build Aegis Agent"
    exit 1
fi

echo "✓ Build completed successfully"
echo ""

# Create service user and group
echo "Creating service user and group..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
    echo "✓ Created user: $SERVICE_USER"
else
    echo "✓ User already exists: $SERVICE_USER"
fi

if ! getent group "$SERVICE_GROUP" &>/dev/null; then
    groupadd -r "$SERVICE_GROUP"
    echo "✓ Created group: $SERVICE_GROUP"
else
    echo "✓ Group already exists: $SERVICE_GROUP"
fi

# Create installation directory
echo "Creating installation directory..."
mkdir -p "$INSTALL_DIR"/{bin,config,logs,data}
echo "✓ Created directory: $INSTALL_DIR"

# Install the binary
echo "Installing Aegis Agent..."
cp aegis "$INSTALL_DIR/bin/"
chmod +x "$INSTALL_DIR/bin/aegis"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
echo "✓ Installed binary to: $INSTALL_DIR/bin/aegis"

# Create configuration file
echo "Creating configuration file..."
cat > "$INSTALL_DIR/config/agent.conf" << EOF
# Aegis Agent Configuration
agent_id = "$AGENT_ID"
backend_url = "ws://$BACKEND_HOST:$BACKEND_PORT/ws/agent"
log_level = "$LOG_LEVEL"
update_interval = "30s"
enabled_modules = ["telemetry", "websocket_communication", "observability"]

# Module configurations
[modules.telemetry]
buffer_size = 1000
flush_interval = "30s"

[modules.observability]
collection_interval = "10s"
anomaly_threshold = 0.8

[modules.websocket_communication]
heartbeat_interval = "30s"
reconnect_interval = "5s"
max_reconnect_attempts = 10
EOF

chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/config/agent.conf"
echo "✓ Created configuration: $INSTALL_DIR/config/agent.conf"

# Create systemd service file
echo "Creating systemd service..."
cat > /etc/systemd/system/aegis-agent.service << EOF
[Unit]
Description=Aegis Agent - Enterprise Security Agent
Documentation=https://github.com/sgerhart/aegis_agent
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/aegis run --config $INSTALL_DIR/config/agent.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aegis-agent

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/logs $INSTALL_DIR/data
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_ADMIN

# Resource limits
LimitNOFILE=65536
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
EOF

echo "✓ Created systemd service: /etc/systemd/system/aegis-agent.service"

# Reload systemd and enable service
echo "Enabling Aegis Agent service..."
systemctl daemon-reload
systemctl enable aegis-agent.service
echo "✓ Service enabled (not started yet)"

# Create log rotation configuration
echo "Creating log rotation configuration..."
cat > /etc/logrotate.d/aegis-agent << EOF
$INSTALL_DIR/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $SERVICE_USER $SERVICE_GROUP
    postrotate
        systemctl reload aegis-agent.service > /dev/null 2>&1 || true
    endscript
}
EOF

echo "✓ Created log rotation: /etc/logrotate.d/aegis-agent"

# Set up eBPF permissions (if needed)
echo "Setting up eBPF permissions..."
if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
    echo "Checking eBPF permissions..."
    if [ "$(cat /proc/sys/kernel/unprivileged_bpf_disabled)" = "1" ]; then
        echo "Warning: eBPF is disabled for unprivileged users"
        echo "The agent may need to run with elevated privileges for eBPF functionality"
    fi
fi

# Create management scripts
echo "Creating management scripts..."
cat > "$INSTALL_DIR/bin/aegis-manage" << 'EOF'
#!/bin/bash
# Aegis Agent Management Script

case "$1" in
    start)
        echo "Starting Aegis Agent..."
        systemctl start aegis-agent.service
        ;;
    stop)
        echo "Stopping Aegis Agent..."
        systemctl stop aegis-agent.service
        ;;
    restart)
        echo "Restarting Aegis Agent..."
        systemctl restart aegis-agent.service
        ;;
    status)
        systemctl status aegis-agent.service
        ;;
    logs)
        journalctl -u aegis-agent.service -f
        ;;
    cli)
        echo "Starting Aegis Agent CLI..."
        /opt/aegis/bin/aegis cli
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|cli}"
        exit 1
        ;;
esac
EOF

chmod +x "$INSTALL_DIR/bin/aegis-manage"
chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/bin/aegis-manage"
echo "✓ Created management script: $INSTALL_DIR/bin/aegis-manage"

# Create symlink for easy access
ln -sf "$INSTALL_DIR/bin/aegis" /usr/local/bin/aegis
ln -sf "$INSTALL_DIR/bin/aegis-manage" /usr/local/bin/aegis-manage
echo "✓ Created symlinks in /usr/local/bin/"

# Test the installation
echo "Testing installation..."
if "$INSTALL_DIR/bin/aegis" version > /dev/null 2>&1; then
    echo "✓ Binary test passed"
else
    echo "Error: Binary test failed"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Deployment Complete                       ║"
echo "║              Aegis Agent Successfully Installed              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Installation Summary:"
echo "  Binary: $INSTALL_DIR/bin/aegis"
echo "  Config: $INSTALL_DIR/config/agent.conf"
echo "  Logs: $INSTALL_DIR/logs/"
echo "  Service: aegis-agent.service"
echo ""
echo "Management Commands:"
echo "  Start:   sudo systemctl start aegis-agent"
echo "  Stop:    sudo systemctl stop aegis-agent"
echo "  Status:  sudo systemctl status aegis-agent"
echo "  Logs:    sudo journalctl -u aegis-agent -f"
echo "  CLI:     aegis cli"
echo "  Manage:  aegis-manage {start|stop|restart|status|logs|cli}"
echo ""
echo "Next Steps:"
echo "  1. Review configuration: $INSTALL_DIR/config/agent.conf"
echo "  2. Start the service: sudo systemctl start aegis-agent"
echo "  3. Check status: sudo systemctl status aegis-agent"
echo "  4. Use CLI: aegis cli"
echo ""
echo "For troubleshooting, check logs: sudo journalctl -u aegis-agent -f"
echo ""

