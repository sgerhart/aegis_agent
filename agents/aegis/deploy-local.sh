#!/bin/bash

# Aegis Agent Local Deployment Script (No sudo required)
# This script deploys the Aegis Agent locally for testing

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                Aegis Agent Local Deployment                 ║"
echo "║              Enterprise Security Agent                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
AGENT_ID="${AEGIS_AGENT_ID:-aegis-agent-001}"
BACKEND_HOST="${AEGIS_BACKEND_HOST:-192.168.1.166}"
BACKEND_PORT="${AEGIS_BACKEND_PORT:-8080}"
LOG_LEVEL="${AEGIS_LOG_LEVEL:-info}"
INSTALL_DIR="${AEGIS_INSTALL_DIR:-./aegis-deploy}"

echo "Configuration:"
echo "  Agent ID: $AGENT_ID"
echo "  Backend: $BACKEND_HOST:$BACKEND_PORT"
echo "  Log Level: $LOG_LEVEL"
echo "  Install Dir: $INSTALL_DIR"
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
mkdir -p "$INSTALL_DIR"/{bin,config,logs,data}
echo "✓ Created directory: $INSTALL_DIR"

# Install the binary
echo "Installing Aegis Agent..."
cp aegis "$INSTALL_DIR/bin/"
chmod +x "$INSTALL_DIR/bin/aegis"
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

echo "✓ Created configuration: $INSTALL_DIR/config/agent.conf"

# Create management scripts
echo "Creating management scripts..."
cat > "$INSTALL_DIR/bin/aegis-manage" << 'EOF'
#!/bin/bash
# Aegis Agent Management Script

AGENT_PID_FILE="./aegis-deploy/logs/agent.pid"

case "$1" in
    start)
        echo "Starting Aegis Agent..."
        if [ -f "$AGENT_PID_FILE" ]; then
            echo "Agent already running (PID: $(cat $AGENT_PID_FILE))"
            exit 1
        fi
        nohup ./aegis-deploy/bin/aegis run --config ./aegis-deploy/config/agent.conf > ./aegis-deploy/logs/agent.log 2>&1 &
        echo $! > "$AGENT_PID_FILE"
        echo "Agent started (PID: $!)"
        ;;
    stop)
        echo "Stopping Aegis Agent..."
        if [ -f "$AGENT_PID_FILE" ]; then
            PID=$(cat "$AGENT_PID_FILE")
            if kill -0 "$PID" 2>/dev/null; then
                kill "$PID"
                rm -f "$AGENT_PID_FILE"
                echo "Agent stopped"
            else
                echo "Agent not running"
                rm -f "$AGENT_PID_FILE"
            fi
        else
            echo "Agent not running"
        fi
        ;;
    restart)
        echo "Restarting Aegis Agent..."
        ./aegis-deploy/bin/aegis-manage stop
        sleep 2
        ./aegis-deploy/bin/aegis-manage start
        ;;
    status)
        if [ -f "$AGENT_PID_FILE" ]; then
            PID=$(cat "$AGENT_PID_FILE")
            if kill -0 "$PID" 2>/dev/null; then
                echo "Agent is running (PID: $PID)"
            else
                echo "Agent is not running"
                rm -f "$AGENT_PID_FILE"
            fi
        else
            echo "Agent is not running"
        fi
        ;;
    logs)
        tail -f ./aegis-deploy/logs/agent.log
        ;;
    cli)
        echo "Starting Aegis Agent CLI..."
        ./aegis-deploy/bin/aegis cli
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|cli}"
        exit 1
        ;;
esac
EOF

chmod +x "$INSTALL_DIR/bin/aegis-manage"
echo "✓ Created management script: $INSTALL_DIR/bin/aegis-manage"

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
echo "  PID File: $INSTALL_DIR/logs/agent.pid"
echo ""
echo "Management Commands:"
echo "  Start:   ./aegis-deploy/bin/aegis-manage start"
echo "  Stop:    ./aegis-deploy/bin/aegis-manage stop"
echo "  Restart: ./aegis-deploy/bin/aegis-manage restart"
echo "  Status:  ./aegis-deploy/bin/aegis-manage status"
echo "  Logs:    ./aegis-deploy/bin/aegis-manage logs"
echo "  CLI:     ./aegis-deploy/bin/aegis cli"
echo ""
echo "Quick Start:"
echo "  1. Start agent: ./aegis-deploy/bin/aegis-manage start"
echo "  2. Check status: ./aegis-deploy/bin/aegis-manage status"
echo "  3. Use CLI: ./aegis-deploy/bin/aegis cli"
echo "  4. View logs: ./aegis-deploy/bin/aegis-manage logs"
echo ""

