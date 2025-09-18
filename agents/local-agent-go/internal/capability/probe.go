package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Probe handles system capability detection
type Probe struct {
	capabilities map[string]interface{}
}

// CapabilityInfo represents system capabilities
type CapabilityInfo struct {
	KernelVersion    string                 `json:"kernel_version"`
	Architecture     string                 `json:"architecture"`
	BTFAvailable     bool                   `json:"btf_available"`
	BPFFeatures      map[string]bool        `json:"bpf_features"`
	HooksAvailable   map[string]bool        `json:"hooks_available"`
	ResourceLimits   map[string]interface{} `json:"resource_limits"`
	Timestamp        string                 `json:"timestamp"`
}

// NewProbe creates a new capability probe
func NewProbe() *Probe {
	return &Probe{
		capabilities: make(map[string]interface{}),
	}
}

// ProbeCapabilities detects system capabilities
func (p *Probe) ProbeCapabilities(ctx context.Context) (*CapabilityInfo, error) {
	info := &CapabilityInfo{
		Architecture:   runtime.GOARCH,
		BPFFeatures:    make(map[string]bool),
		HooksAvailable: make(map[string]bool),
		ResourceLimits: make(map[string]interface{}),
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}

	// Get kernel version
	if err := p.probeKernelVersion(info); err != nil {
		return nil, fmt.Errorf("failed to probe kernel version: %w", err)
	}

	// Check BTF availability
	if err := p.probeBTF(info); err != nil {
		return nil, fmt.Errorf("failed to probe BTF: %w", err)
	}

	// Check BPF features
	if err := p.probeBPFFeatures(info); err != nil {
		return nil, fmt.Errorf("failed to probe BPF features: %w", err)
	}

	// Check available hooks
	if err := p.probeHooks(info); err != nil {
		return nil, fmt.Errorf("failed to probe hooks: %w", err)
	}

	// Check resource limits
	if err := p.probeResourceLimits(info); err != nil {
		return nil, fmt.Errorf("failed to probe resource limits: %w", err)
	}

	return info, nil
}

// probeKernelVersion detects the kernel version
func (p *Probe) probeKernelVersion(info *CapabilityInfo) error {
	// Try to read from /proc/sys/kernel/osrelease
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.KernelVersion = strings.TrimSpace(string(data))
		return nil
	}

	// Fallback to uname command
	cmd := exec.CommandContext(context.Background(), "uname", "-r")
	if output, err := cmd.Output(); err == nil {
		info.KernelVersion = strings.TrimSpace(string(output))
		return nil
	}

	info.KernelVersion = "unknown"
	return nil
}

// probeBTF checks if BTF is available
func (p *Probe) probeBTF(info *CapabilityInfo) error {
	// Check if BTF data is available
	if _, err := btf.LoadKernelSpec(); err != nil {
		info.BTFAvailable = false
	} else {
		info.BTFAvailable = true
	}

	return nil
}

// probeBPFFeatures checks available BPF features
func (p *Probe) probeBPFFeatures(info *CapabilityInfo) error {
	features := map[string]bool{
		"kprobe":      false,
		"kretprobe":   false,
		"tracepoint":  false,
		"xdp":         false,
		"tc":          false,
		"cgroup":      false,
		"perf_event":  false,
		"raw_tracepoint": false,
	}

	// Test each feature by trying to create a simple program
	for feature := range features {
		if p.testBPFFeature(feature) {
			features[feature] = true
		}
	}

	info.BPFFeatures = features
	return nil
}

// testBPFFeature tests if a specific BPF feature is available
func (p *Probe) testBPFFeature(feature string) bool {
	// For now, we'll use a simplified approach
	// In a real implementation, you would test each feature individually
	
	// Check if eBPF is available by trying to load a simple program
	spec := &ebpf.ProgramSpec{
		Type:       ebpf.Kprobe,
		AttachType: ebpf.AttachNone,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	}

	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		return false
	}
	defer prog.Close()

	return true
}

// probeHooks checks available hook points
func (p *Probe) probeHooks(info *CapabilityInfo) error {
	hooks := map[string]bool{
		"syscalls":     false,
		"network":      false,
		"filesystem":   false,
		"scheduler":    false,
		"memory":       false,
		"security":     false,
	}

	// Check for common hook points
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); err == nil {
		hooks["syscalls"] = true
	}

	if _, err := os.Stat("/sys/kernel/debug/tracing/events/net"); err == nil {
		hooks["network"] = true
	}

	if _, err := os.Stat("/sys/kernel/debug/tracing/events/vfs"); err == nil {
		hooks["filesystem"] = true
	}

	if _, err := os.Stat("/sys/kernel/debug/tracing/events/sched"); err == nil {
		hooks["scheduler"] = true
	}

	if _, err := os.Stat("/sys/kernel/debug/tracing/events/kmem"); err == nil {
		hooks["memory"] = true
	}

	if _, err := os.Stat("/sys/kernel/debug/tracing/events/security"); err == nil {
		hooks["security"] = true
	}

	info.HooksAvailable = hooks
	return nil
}

// probeResourceLimits checks system resource limits
func (p *Probe) probeResourceLimits(info *CapabilityInfo) error {
	limits := make(map[string]interface{})

	// Check BPF-related limits
	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		limits["unprivileged_bpf_disabled"] = strings.TrimSpace(string(data))
	}

	if data, err := os.ReadFile("/proc/sys/kernel/bpf_jit_enable"); err == nil {
		limits["bpf_jit_enable"] = strings.TrimSpace(string(data))
	}

	if data, err := os.ReadFile("/proc/sys/kernel/bpf_jit_harden"); err == nil {
		limits["bpf_jit_harden"] = strings.TrimSpace(string(data))
	}

	// Check memory limits
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				limits["memtotal"] = strings.TrimSpace(strings.TrimPrefix(line, "MemTotal:"))
				break
			}
		}
	}

	// Check CPU info
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		cpuCount := 0
		for _, line := range lines {
			if strings.HasPrefix(line, "processor") {
				cpuCount++
			}
		}
		limits["cpu_count"] = cpuCount
	}

	info.ResourceLimits = limits
	return nil
}

// PublishCapabilities publishes capability information to NATS
func (p *Probe) PublishCapabilities(ctx context.Context, natsConn interface{}, hostID string) error {
	capabilities, err := p.ProbeCapabilities(ctx)
	if err != nil {
		return fmt.Errorf("failed to probe capabilities: %w", err)
	}

	// Marshal to JSON
	data, err := json.Marshal(capabilities)
	if err != nil {
		return fmt.Errorf("failed to marshal capabilities: %w", err)
	}

	// Publish to NATS (this would need to be implemented based on your NATS setup)
	// For now, just log the capabilities
	fmt.Printf("Agent capabilities for host %s: %s\n", hostID, string(data))

	return nil
}
