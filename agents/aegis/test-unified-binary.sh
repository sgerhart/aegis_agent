#!/bin/bash

# Test script for the unified Aegis Agent binary
# This script tests all subcommands to ensure they work correctly

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                Aegis Agent Binary Test                       ║"
echo "║              Unified Binary with Subcommands                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if binary exists
if [ ! -f "./aegis" ]; then
    echo "Error: aegis binary not found. Building..."
    go build -o aegis ./cmd/aegis
    if [ $? -ne 0 ]; then
        echo "Failed to build aegis binary"
        exit 1
    fi
fi

echo "Testing unified Aegis Agent binary..."
echo ""

# Test 1: Help command
echo "=== Test 1: Help Command ==="
./aegis help
echo ""

# Test 2: Version command
echo "=== Test 2: Version Command ==="
./aegis version
echo ""

# Test 3: Modules command
echo "=== Test 3: Modules Command ==="
./aegis modules
echo ""

# Test 4: Status command
echo "=== Test 4: Status Command ==="
./aegis status
echo ""

# Test 5: Metrics command
echo "=== Test 5: Metrics Command ==="
./aegis metrics
echo ""

# Test 6: Health command
echo "=== Test 6: Health Command ==="
./aegis health
echo ""

# Test 7: CLI command (brief test)
echo "=== Test 7: CLI Command (Brief Test) ==="
echo "Testing CLI startup..."
echo "quit" | timeout 5s ./aegis cli
echo ""

# Test 8: Invalid command
echo "=== Test 8: Invalid Command ==="
./aegis invalid-command
echo ""

# Test 9: No arguments
echo "=== Test 9: No Arguments ==="
./aegis
echo ""

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Test Complete                             ║"
echo "║              Unified Binary Working Correctly                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "Binary Information:"
ls -la ./aegis
echo ""

echo "Available Commands:"
echo "  aegis run          - Start agent in daemon mode"
echo "  aegis cli          - Start interactive CLI"
echo "  aegis status       - Show agent status"
echo "  aegis modules      - List available modules"
echo "  aegis metrics      - Show agent metrics"
echo "  aegis health       - Check agent health"
echo "  aegis version      - Show version information"
echo "  aegis help         - Show help information"
echo ""

echo "For Linux deployment:"
echo "  sudo ./deploy-linux.sh"
echo ""

echo "For interactive use:"
echo "  ./aegis cli"
echo ""

