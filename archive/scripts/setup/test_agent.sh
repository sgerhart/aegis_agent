#!/bin/bash

# Test Aegis Agent on Linux Host
REMOTE_HOST=${1:-192.168.193.129}
REMOTE_USER=${2:-steve}
SSH_KEY=~/.ssh/aegis_agent_key

echo "🧪 Testing Aegis Agent"
echo "====================="

echo -e "\n1️⃣ Agent Status:"
ssh -i $SSH_KEY $REMOTE_USER@$REMOTE_HOST "curl -s http://localhost:7070/status | jq ."

echo -e "\n2️⃣ Agent Info:"
ssh -i $SSH_KEY $REMOTE_USER@$REMOTE_HOST "curl -s http://localhost:7070/info | jq ."

echo -e "\n3️⃣ eBPF Maps:"
ssh -i $SSH_KEY $REMOTE_USER@$REMOTE_HOST "echo 'C!sco#123' | sudo -S bpftool map list | grep -E '(policy|allow|mode)'"

echo -e "\n4️⃣ Agent Logs:"
ssh -i $SSH_KEY $REMOTE_USER@$REMOTE_HOST "echo 'C!sco#123' | sudo -S journalctl -u aegis --since '2 minutes ago' --no-pager | tail -5"
