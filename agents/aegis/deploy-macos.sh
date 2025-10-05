#!/bin/bash

# Aegis Agent macOS Deployment Script
# This script builds and deploys the Aegis Agent on macOS

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                Aegis Agent macOS Deployment                  ║"
echo "║              Enterprise Security Agent                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
AGENT_ID="${AEGIS_AGENT_ID:-aegis-agent-001}"
BACKEND_HOST="${AEGIS_BACKEND_HOST:-192.168.1.166}"
BACKEND_PORT="${AEGIS_BACKEND_PORT:-8080}"
LOG_LEVEL="${AEGIS_LOG_LEVEL:-info}"
INSTALL_DIR="${AEGIS_INSTALL_DIR:-/usr/local/aegis}"
SERVICE_USER="${AEGIS_SERVICE_USER:-$(whoami)}"

echo "Configuration:"
echo "  Agent ID: $AGENT_ID"
echo "  Backend: $BACKEND_HOST:$BACKEND_PORT"
echo "  Log Level: $LOG_LEVEL"
echo "  Install Dir: $INSTALL_DIR"
echo "  Service User: $SERVICE_USER"
echo ""

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

# Set build flags for macOS
export GOOS=darwin
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

# Create installation directory
echo "Creating installation directory..."
sudo mkdir -p "$INSTALL_DIR"/{bin,config,logs,data}
echo "✓ Created directory: $INSTALL_DIR"

# Install the binary
echo "Installing Aegis Agent..."
sudo cp aegis "$INSTALL_DIR/bin/"
sudo chmod +x "$INSTALL_DIR/bin/aegis"
sudo chown -R "$SERVICE_USER:staff" "$INSTALL_DIR"
echo "✓ Installed binary to: $INSTALL_DIR/bin/aegis"

# Create configuration file
echo "Creating configuration file..."
sudo tee "$INSTALL_DIR/config/agent.conf" > /dev/null << EOF
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

sudo chown "$SERVICE_USER:staff" "$INSTALL_DIR/config/agent.conf"
echo "✓ Created configuration: $INSTALL_DIR/config/agent.conf"

# Create launchd plist for service management
echo "Creating launchd service..."
sudo tee /Library/LaunchDaemons/com.aegis.agent.plist > /dev/null << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aegis.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/bin/aegis</string>
        <string>run</string>
        <string>--config</string>
        <string>$INSTALL_DIR/config/agent.conf</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/logs/agent.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/logs/agent.error.log</string>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>UserName</key>
    <string>$SERVICE_USER</string>
    <key>GroupName</key>
    <string>staff</string>
</dict>
</plist>
EOF

echo "✓ Created launchd service: /Library/LaunchDaemons/com.aegis.agent.plist"

# Create management scripts
echo "Creating management scripts..."
sudo tee "$INSTALL_DIR/bin/aegis-manage" > /dev/null << 'EOF'
#!/bin/bash
# Aegis Agent Management Script

case "$1" in
    start)
        echo "Starting Aegis Agent..."
        sudo launchctl load /Library/LaunchDaemons/com.aegis.agent.plist
        ;;
    stop)
        echo "Stopping Aegis Agent..."
        sudo launchctl unload /Library/LaunchDaemons/com.aegis.agent.plist
        ;;
    restart)
        echo "Restarting Aegis Agent..."
        sudo launchctl unload /Library/LaunchDaemons/com.aegis.agent.plist
        sleep 2
        sudo launchctl load /Library/LaunchDaemons/com.aegis.agent.plist
        ;;
    status)
        launchctl list | grep com.aegis.agent
        ;;
    logs)
        tail -f /usr/local/aegis/logs/agent.log
        ;;
    cli)
        echo "Starting Aegis Agent CLI..."
        /usr/local/aegis/bin/aegis cli
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|cli}"
        exit 1
        ;;
esac
EOF

sudo chmod +x "$INSTALL_DIR/bin/aegis-manage"
sudo chown "$SERVICE_USER:staff" "$INSTALL_DIR/bin/aegis-manage"
echo "✓ Created management script: $INSTALL_DIR/bin/aegis-manage"

# Create symlinks for easy access
sudo ln -sf "$INSTALL_DIR/bin/aegis" /usr/local/bin/aegis
sudo ln -sf "$INSTALL_DIR/bin/aegis-manage" /usr/local/bin/aegis-manage
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
echo "  Service: com.aegis.agent (launchd)"
echo ""
echo "Management Commands:"
echo "  Start:   aegis-manage start"
echo "  Stop:    aegis-manage stop"
echo "  Restart: aegis-manage restart"
echo "  Status:  aegis-manage status"
echo "  Logs:    aegis-manage logs"
echo "  CLI:     aegis cli"
echo ""
echo "Next Steps:"
echo "  1. Review configuration: $INSTALL_DIR/config/agent.conf"
echo "  2. Start the service: aegis-manage start"
echo "  3. Check status: aegis-manage status"
echo "  4. Use CLI: aegis cli"
echo ""
echo "For troubleshooting, check logs: aegis-manage logs"
echo ""

