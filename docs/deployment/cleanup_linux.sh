#!/bin/bash

# Cleanup script for Linux host
echo "Cleaning up agent binaries and processes..."

# Kill any running agent processes
sudo pkill -f aegis-agent 2>/dev/null || true
sudo pkill -f aegis 2>/dev/null || true

# Remove agent binaries from /tmp
sudo rm -f /tmp/aegis-agent

# Remove old agent binaries from /opt/aegis/bin (keep the main one)
sudo rm -f /opt/aegis/bin/aegis.backup*
sudo rm -f /opt/aegis/bin/aegis-with-polling.backup
sudo rm -f /opt/aegis/bin/aegis-polling

# Check what's left
echo "Remaining agent files:"
find /opt/aegis -name '*aegis*' -type f 2>/dev/null
find /tmp -name '*aegis*' -type f 2>/dev/null

echo "Cleanup complete!"
