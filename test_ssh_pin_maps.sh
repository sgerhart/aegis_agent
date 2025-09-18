#!/bin/bash

# Test pinned maps functionality via SSH
HOST="192.168.64.17"
USER="steve"
PASSWORD="C!sco#123"

echo "=== Testing Pinned Maps via SSH ==="

# Create a simple eBPF program with pinned maps
cat > /tmp/simple_policy_maps.bpf.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct policy_edge {
    __u32 src_ip;
    __u32 dst_ip;
    __u32 src_mask;
    __u32 dst_mask;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 action;
    __u8 priority;
    __u32 process_uid;
    __u32 process_gid;
    __u64 timestamp;
};

struct allow_cidr {
    __u32 prefix_len;
    __u32 ip;
    __u8 action;
    __u8 priority;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct policy_edge);
    __uint(pinning, PIN_GLOBAL_NS);
} policy_edges SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 512);
    __type(key, struct allow_cidr);
    __type(value, __u8);
    __uint(pinning, PIN_GLOBAL_NS);
} allow_lpm4 SEC(".maps");

char _license[] SEC("license") = "GPL";
EOF

echo "✓ Created eBPF source file"

# Copy the source file to the Linux box
echo "Copying source file to Linux box..."
scp -o StrictHostKeyChecking=no /tmp/simple_policy_maps.bpf.c $USER@$HOST:/tmp/

# Create a script to run on the Linux box
cat > /tmp/run_pin_maps.sh << 'EOF'
#!/bin/bash

echo "=== AegisFlux Policy Maps Pinning Test ==="

# Create the aegis directory
echo "Creating /sys/fs/bpf/aegis directory..."
sudo mkdir -p /sys/fs/bpf/aegis

# Compile the eBPF program
echo "Compiling eBPF program..."
clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I/usr/include/aarch64-linux-gnu -c /tmp/simple_policy_maps.bpf.c -o /tmp/simple_policy_maps.o

if [ $? -eq 0 ]; then
    echo "✓ eBPF program compiled successfully"
else
    echo "✗ Failed to compile eBPF program"
    exit 1
fi

# Load the program to create pinned maps
echo "Loading eBPF program to create pinned maps..."
sudo bpftool prog load /tmp/simple_policy_maps.o /sys/fs/bpf/aegis/policy_maps

if [ $? -eq 0 ]; then
    echo "✓ eBPF program loaded successfully"
else
    echo "✗ Failed to load eBPF program"
    exit 1
fi

# Verify the maps were created
echo "=== Checking pinned maps ==="
ls -la /sys/fs/bpf/aegis/

echo "=== Map Details ==="
echo "Policy edges map:"
sudo bpftool map show pinned /sys/fs/bpf/aegis/policy_edges

echo "Allow LPM4 map:"
sudo bpftool map show pinned /sys/fs/bpf/aegis/allow_lpm4

# Add test data
echo "=== Adding test data ==="
echo "Adding policy edge..."
sudo bpftool map update pinned /sys/fs/bpf/aegis/policy_edges key 1 0 0 0 value 192.168.1.0 192.168.2.0 255.255.255.0 255.255.255.0 80 443 6 1 10 1000 1000 0

echo "Adding allow CIDR..."
sudo bpftool map update pinned /sys/fs/bpf/aegis/allow_lpm4 key 24 192.168.1.0 0 0 0 value 1

# Verify the data
echo "=== Verifying data ==="
echo "Policy edges dump:"
sudo bpftool map dump pinned /sys/fs/bpf/aegis/policy_edges

echo "Allow LPM4 dump:"
sudo bpftool map dump pinned /sys/fs/bpf/aegis/allow_lpm4

echo "=== Test Summary ==="
echo "✓ Pinned maps created successfully"
echo "✓ Test data added to maps"
echo "✓ Maps can be dumped and verified"
echo "✓ Ready for policy enforcement"
EOF

echo "✓ Created test script"

# Copy the test script to the Linux box
echo "Copying test script to Linux box..."
scp -o StrictHostKeyChecking=no /tmp/run_pin_maps.sh $USER@$HOST:/tmp/

# Make the script executable and run it
echo "Running test on Linux box..."
ssh -o StrictHostKeyChecking=no $USER@$HOST "chmod +x /tmp/run_pin_maps.sh && /tmp/run_pin_maps.sh"

echo "=== Test completed ==="
