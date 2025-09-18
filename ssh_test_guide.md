# SSH Test Guide for Pinned Maps

## Manual SSH Testing Steps

Since the automated SSH connection is having authentication issues, here's a manual approach to test the pinned maps functionality on the Linux box:

### Step 1: Connect to Linux Box
```bash
ssh steve@192.168.64.17
# Password: C!sco#123
```

### Step 2: Create eBPF Source File
```bash
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
```

### Step 3: Create Aegis Directory
```bash
sudo mkdir -p /sys/fs/bpf/aegis
```

### Step 4: Compile eBPF Program
```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I/usr/include/aarch64-linux-gnu -c /tmp/simple_policy_maps.bpf.c -o /tmp/simple_policy_maps.o
```

### Step 5: Load Program to Create Pinned Maps
```bash
sudo bpftool prog load /tmp/simple_policy_maps.o /sys/fs/bpf/aegis/policy_maps
```

### Step 6: Verify Maps Were Created
```bash
ls -la /sys/fs/bpf/aegis/
sudo bpftool map show pinned /sys/fs/bpf/aegis/policy_edges
sudo bpftool map show pinned /sys/fs/bpf/aegis/allow_lpm4
```

### Step 7: Add Test Data
```bash
# Add policy edge
sudo bpftool map update pinned /sys/fs/bpf/aegis/policy_edges key 1 0 0 0 value 192.168.1.0 192.168.2.0 255.255.255.0 255.255.255.0 80 443 6 1 10 1000 1000 0

# Add allow CIDR
sudo bpftool map update pinned /sys/fs/bpf/aegis/allow_lpm4 key 24 192.168.1.0 0 0 0 value 1
```

### Step 8: Verify Data
```bash
sudo bpftool map dump pinned /sys/fs/bpf/aegis/policy_edges
sudo bpftool map dump pinned /sys/fs/bpf/aegis/allow_lpm4
```

## Expected Results

If successful, you should see:
- ✅ Maps created under `/sys/fs/bpf/aegis/`
- ✅ Policy edge data showing `192.168.1.0 -> 192.168.2.0` (TCP 80->443, ALLOW)
- ✅ Allow CIDR data showing `192.168.1.0/24` (ALLOW)
- ✅ Maps can be dumped and verified

## Troubleshooting

If you encounter permission issues:
1. Make sure you're using `sudo` for all bpftool commands
2. Check that the user has permission to access `/sys/fs/bpf/`
3. Verify that eBPF is enabled in the kernel

## Alternative: Use the Demo Program

If the manual approach doesn't work, you can use the demo program we created:

```bash
# On your local machine
cd /Users/stevengerhart/workspace/github/sgerhart/aegis_agent/agents/local-agent-go
go run ./cmd/pin_maps_demo
```

This will create mock pinned maps that demonstrate the functionality.
