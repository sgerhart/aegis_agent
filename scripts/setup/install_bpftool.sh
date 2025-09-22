#!/bin/bash

# Standalone bpftool installer for ARM64 Linux
# Run this if bpftool installation fails in the main setup

echo "🔧 Installing bpftool for ARM64 Linux"
echo "Architecture: $(uname -m)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"

# Check if already installed
if command -v bpftool >/dev/null 2>&1; then
    echo "✅ bpftool already available:"
    bpftool version
    exit 0
fi

# Method 1: Try package managers with different names
echo "📦 Trying package installation..."

if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    
    # Try different package names
    if apt-get install -y bpftool 2>/dev/null; then
        echo "✅ Installed bpftool package"
        exit 0
    elif apt-get install -y linux-tools-$(uname -r) 2>/dev/null; then
        echo "✅ Installed via linux-tools"
        # Find and symlink bpftool
        find /usr -name bpftool -type f 2>/dev/null | head -1 | xargs -I {} ln -sf {} /usr/local/bin/bpftool
        exit 0
    elif apt-get install -y linux-tools-generic 2>/dev/null; then
        echo "✅ Installed via linux-tools-generic"
        find /usr -name bpftool -type f 2>/dev/null | head -1 | xargs -I {} ln -sf {} /usr/local/bin/bpftool
        exit 0
    fi
    
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y bpftool || echo "Package installation failed"
    
elif command -v yum >/dev/null 2>&1; then
    yum install -y bpftool || echo "Package installation failed"
fi

# Method 2: Download pre-built binary (if available)
echo "📥 Trying pre-built binary download..."

# Check for pre-built binaries
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    # Try to download from known sources
    if wget -q -O /tmp/bpftool https://github.com/libbpf/bpftool/releases/latest/download/bpftool-arm64; then
        chmod +x /tmp/bpftool
        mv /tmp/bpftool /usr/local/bin/bpftool
        ln -sf /usr/local/bin/bpftool /usr/sbin/bpftool
        echo "✅ Downloaded pre-built bpftool"
        bpftool version
        exit 0
    fi
fi

# Method 3: Build from source
echo "🔨 Building bpftool from source..."

# Install build dependencies
if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y build-essential libelf-dev zlib1g-dev pkg-config
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc make elfutils-libelf-devel zlib-devel pkgconfig
elif command -v yum >/dev/null 2>&1; then
    yum install -y gcc make elfutils-libelf-devel zlib-devel pkgconfig
fi

cd /tmp

# Try different source options
if git clone --depth 1 https://github.com/libbpf/bpftool.git; then
    echo "📁 Using standalone bpftool repository"
    cd bpftool/src
    
elif wget -q https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.tar.xz && tar -xf linux-6.1.tar.xz; then
    echo "📁 Using kernel source tree"
    cd linux-6.1/tools/bpf/bpftool
    
else
    echo "❌ Failed to download source"
    exit 1
fi

# Build
echo "⚙️  Compiling bpftool..."
if make -j$(nproc) 2>/dev/null || make; then
    echo "✅ Build successful"
    
    # Install
    cp bpftool /usr/local/bin/bpftool
    chmod +x /usr/local/bin/bpftool
    ln -sf /usr/local/bin/bpftool /usr/sbin/bpftool
    
    # Cleanup
    cd /
    rm -rf /tmp/bpftool /tmp/linux-*
    
    echo "✅ bpftool installed successfully"
    /usr/local/bin/bpftool version
    
else
    echo "❌ Build failed"
    exit 1
fi
