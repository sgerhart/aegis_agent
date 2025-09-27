#!/bin/bash

# Aegis Agent Runner Script (Clean Version)
# Usage: ./run-agent-clean.sh [production|debug] [options]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Default values
MODE="production"
AGENT_ID="aegis-agent-$(date +%s)"
BACKEND_URL="ws://192.168.1.157:8080/ws/agent"
LOG_LEVEL="info"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        production|debug)
            MODE="$1"
            shift
            ;;
        --agent-id)
            AGENT_ID="$2"
            shift 2
            ;;
        --backend-url)
            BACKEND_URL="$2"
            shift 2
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --help|-h)
            echo "Aegis Agent Runner (Clean Version)"
            echo ""
            echo "Usage: $0 [production|debug] [options]"
            echo ""
            echo "Modes:"
            echo "  production  - Run production agent (optimized, minimal logging)"
            echo "  debug       - Run debug agent (enhanced logging, verbose output)"
            echo ""
            echo "Options:"
            echo "  --agent-id ID        Agent ID (default: aegis-agent-TIMESTAMP)"
            echo "  --backend-url URL    Backend WebSocket URL (default: ws://192.168.1.157:8080/ws/agent)"
            echo "  --log-level LEVEL    Log level: debug, info, warn, error (default: info)"
            echo "  --help, -h           Show this help"
            echo ""
            echo "Examples:"
            echo "  $0 production"
            echo "  $0 debug --agent-id my-agent --log-level debug"
            echo "  $0 production --backend-url ws://backend:8080/ws/agent"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Use the production agent binary
BINARY="aegis-agent"
if [ "$MODE" = "production" ]; then
    echo "🚀 Starting Aegis Agent (Production Mode)"
elif [ "$MODE" = "debug" ]; then
    echo "🔧 Starting Aegis Agent (Debug Mode)"
    LOG_LEVEL="debug"  # Force debug logging for debug mode
else
    echo "❌ Invalid mode: $MODE"
    echo "Use 'production' or 'debug'"
    exit 1
fi

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "❌ Binary not found: $BINARY"
    echo "Available binaries:"
    ls -la aegis-agent* 2>/dev/null || echo "No agent binaries found"
    echo ""
    echo "Build the agent first:"
    echo "  cd agents/aegis && make build"
    exit 1
fi

# Display configuration
echo "📋 Configuration:"
echo "  Mode: $MODE"
echo "  Binary: $BINARY"
echo "  Agent ID: $AGENT_ID"
echo "  Backend URL: $BACKEND_URL"
echo "  Log Level: $LOG_LEVEL"
echo ""

# Run the agent
echo "▶️  Starting agent..."
exec ./"$BINARY" \
    --agent-id "$AGENT_ID" \
    --backend-url "$BACKEND_URL" \
    --log-level "$LOG_LEVEL"
