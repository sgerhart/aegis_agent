#!/bin/bash

# Setup SSH Key Authentication for Linux Host
# Usage: ./setup_ssh_key.sh

HOST="192.168.193.128"
USER="steve"
KEY_NAME="aegis_agent_key"

echo "🔑 Setting up SSH key authentication for $USER@$HOST"

# Check if key already exists
if [ ! -f ~/.ssh/$KEY_NAME ]; then
    echo "📝 Generating new SSH key pair..."
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/$KEY_NAME -N "" -C "aegis-agent-key-$(date +%Y%m%d)"
    echo "✅ SSH key pair generated: ~/.ssh/$KEY_NAME"
else
    echo "✅ SSH key already exists: ~/.ssh/$KEY_NAME"
fi

echo ""
echo "📋 Next steps to complete SSH setup:"
echo ""
echo "1. Copy the public key to your clipboard:"
echo "   cat ~/.ssh/$KEY_NAME.pub"
echo ""
echo "2. On the Linux host ($HOST), run as user $USER:"
echo "   mkdir -p ~/.ssh"
echo "   echo 'PASTE_YOUR_PUBLIC_KEY_HERE' >> ~/.ssh/authorized_keys"
echo "   chmod 700 ~/.ssh"
echo "   chmod 600 ~/.ssh/authorized_keys"
echo ""
echo "3. Or, if you can use password authentication once:"
echo "   ssh-copy-id -i ~/.ssh/$KEY_NAME.pub $USER@$HOST"
echo ""
echo "4. Test the connection:"
echo "   ssh -i ~/.ssh/$KEY_NAME $USER@$HOST 'echo Success'"
echo ""

# Display the public key
echo "🔑 Your public key to copy:"
echo "----------------------------------------"
cat ~/.ssh/$KEY_NAME.pub
echo "----------------------------------------"
echo ""
echo "💡 Alternative: You can manually SSH to the host and paste this key into ~/.ssh/authorized_keys"
