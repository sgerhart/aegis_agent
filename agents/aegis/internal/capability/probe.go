package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Probe handles system capability detection
type Probe struct {
	hostID string
}

// CapabilityInfo contains detected system capabilities
type CapabilityInfo struct {
	HostID           string                 `json:"host_id"`
	KernelVersion    string                 `json:"kernel_version"`
	BTFAvailable     bool                   `json:"btf_available"`
	BPFFeatures      map[string]bool        `json:"bpf_features"`
	HookPoints       map[string]bool        `json:"hook_points"`
	ResourceLimits   map[string]interface{} `json:"resource_limits"`
	Timestamp        string                 `json:"timestamp"`
}

// BPFFeature represents a specific BPF feature
type BPFFeature struct {
	Name        string `json:"name"`
	Available   bool   `json:"available"`
	Description string `json:"description"`
}

// HookPoint represents an eBPF hook point
type HookPoint struct {
	Name        string `json:"name"`
	Available   bool   `json:"available"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

// NewProbe creates a new capability probe
func NewProbe() *Probe {
	return &Probe{}
}

// ProbeCapabilities detects system capabilities for eBPF segmentation
func (p *Probe) ProbeCapabilities(ctx context.Context) (*CapabilityInfo, error) {
	info := &CapabilityInfo{
		HostID:        p.hostID,
		BPFFeatures:   make(map[string]bool),
		HookPoints:    make(map[string]bool),
		ResourceLimits: make(map[string]interface{}),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}
	
	// Probe kernel version
	if err := p.probeKernelVersion(info); err != nil {
		return nil, fmt.Errorf("kernel version probe failed: %w", err)
	}
	
	// Probe BTF availability
	if err := p.probeBTF(info); err != nil {
		return nil, fmt.Errorf("BTF probe failed: %w", err)
	}
	
	// Probe BPF features
	if err := p.probeBPFFeatures(info); err != nil {
		return nil, fmt.Errorf("BPF features probe failed: %w", err)
	}
	
	// Probe hook points
	if err := p.probeHookPoints(info); err != nil {
		return nil, fmt.Errorf("hook points probe failed: %w", err)
	}
	
	// Probe resource limits
	if err := p.probeResourceLimits(info); err != nil {
		return nil, fmt.Errorf("resource limits probe failed: %w", err)
	}
	
	return info, nil
}

// probeKernelVersion detects kernel version
func (p *Probe) probeKernelVersion(info *CapabilityInfo) error {
	// Read kernel version from /proc/version
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return fmt.Errorf("failed to read /proc/version: %w", err)
	}
	
	version := strings.TrimSpace(string(data))
	info.KernelVersion = version
	
	// Extract version number
	parts := strings.Fields(version)
	if len(parts) >= 3 {
		info.KernelVersion = parts[2] // Usually the version number
	}
	
	return nil
}

// probeBTF checks BTF availability
func (p *Probe) probeBTF(info *CapabilityInfo) error {
	// Check if BTF is available
	btfPath := "/sys/kernel/btf/vmlinux"
	if _, err := os.Stat(btfPath); err == nil {
		info.BTFAvailable = true
		
		// Try to load BTF to verify it's valid
		spec, err := btf.LoadKernelSpec()
		if err == nil {
			info.BTFAvailable = true
			spec.Close()
		} else {
			info.BTFAvailable = false
		}
	} else {
		info.BTFAvailable = false
	}
	
	return nil
}

// probeBPFFeatures detects available BPF features
func (p *Probe) probeBPFFeatures(info *CapabilityInfo) error {
	features := map[string]bool{
		"xdp":              false,
		"tc":               false,
		"cgroup":           false,
		"kprobe":           false,
		"kretprobe":        false,
		"tracepoint":       false,
		"raw_tracepoint":   false,
		"perf_event":       false,
		"lsm":              false,
		"sk_lookup":        false,
		"sk_skb":           false,
		"sk_msg":           false,
		"sk_reuseport":     false,
		"flow_dissector":   false,
		"cgroup_sock":      false,
		"cgroup_sock_addr": false,
		"cgroup_sysctl":    false,
		"cgroup_sockopt":   false,
		"cgroup_skb":       false,
		"cgroup_sk":        false,
		"cgroup_device":    false,
		"cgroup_sock_create": false,
		"cgroup_sock_release": false,
		"cgroup_sock_bind":   false,
		"cgroup_sock_connect": false,
		"cgroup_sock_listen":  false,
		"cgroup_sock_accept":  false,
		"cgroup_sock_getpeername": false,
		"cgroup_sock_getsockname": false,
		"cgroup_sock_getsockopt":  false,
		"cgroup_sock_setsockopt":  false,
		"cgroup_sock_shutdown":    false,
		"cgroup_sock_sendmsg":     false,
		"cgroup_sock_recvmsg":     false,
		"cgroup_sock_connect4":    false,
		"cgroup_sock_connect6":    false,
		"cgroup_sock_getpeername4": false,
		"cgroup_sock_getpeername6": false,
		"cgroup_sock_getsockname4": false,
		"cgroup_sock_getsockname6": false,
		"cgroup_sock_sendmsg4":     false,
		"cgroup_sock_sendmsg6":     false,
		"cgroup_sock_recvmsg4":     false,
		"cgroup_sock_recvmsg6":     false,
		"cgroup_sock_sendmsg4":     false,
		"cgroup_sock_sendmsg6":     false,
		"cgroup_sock_recvmsg4":     false,
		"cgroup_sock_recvmsg6":     false,
	}
	
	// Test each feature by trying to create a program
	for feature := range features {
		features[feature] = p.testBPFFeature(feature)
	}
	
	info.BPFFeatures = features
	return nil
}

// testBPFFeature tests if a specific BPF feature is available
func (p *Probe) testBPFFeature(feature string) bool {
	// Map feature names to program types
	programTypes := map[string]ebpf.ProgramType{
		"xdp":              ebpf.XDP,
		"tc":               ebpf.SchedCLS,
		"cgroup":           ebpf.CGroupDevice,
		"kprobe":           ebpf.Kprobe,
		"kretprobe":        ebpf.Kprobe,
		"tracepoint":       ebpf.TracePoint,
		"raw_tracepoint":   ebpf.RawTracepoint,
		"perf_event":       ebpf.PerfEvent,
		"lsm":              ebpf.LSM,
		"sk_lookup":        ebpf.SkLookup,
		"sk_skb":           ebpf.SkSKB,
		"sk_msg":           ebpf.SkMsg,
		"sk_reuseport":     ebpf.SkReuseport,
		"flow_dissector":   ebpf.FlowDissector,
		"cgroup_sock":      ebpf.CGroupSock,
		"cgroup_sock_addr": ebpf.CGroupSockAddr,
		"cgroup_sysctl":    ebpf.CGroupSysctl,
		"cgroup_sockopt":   ebpf.CGroupSockopt,
		"cgroup_skb":       ebpf.CGroupSKB,
		"cgroup_sk":        ebpf.CGroupSK,
		"cgroup_device":    ebpf.CGroupDevice,
	}
	
	progType, exists := programTypes[feature]
	if !exists {
		return false
	}
	
	// Create a minimal program spec
	spec := &ebpf.ProgramSpec{
		Type:       progType,
		AttachType: ebpf.AttachNone,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	}
	
	// Try to create the program
	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		return false
	}
	defer prog.Close()
	
	return true
}

// probeHookPoints detects available hook points
func (p *Probe) probeHookPoints(info *CapabilityInfo) error {
	hookPoints := map[string]bool{
		"xdp":              false,
		"tc_ingress":       false,
		"tc_egress":        false,
		"cgroup_connect4":  false,
		"cgroup_connect6":  false,
		"cgroup_sendmsg4":  false,
		"cgroup_sendmsg6":  false,
		"cgroup_recvmsg4":  false,
		"cgroup_recvmsg6":  false,
		"kprobe":           false,
		"kretprobe":        false,
		"tracepoint":       false,
		"raw_tracepoint":   false,
		"perf_event":       false,
		"lsm":              false,
	}
	
	// Test hook points
	for hook := range hookPoints {
		hookPoints[hook] = p.testHookPoint(hook)
	}
	
	info.HookPoints = hookPoints
	return nil
}

// testHookPoint tests if a hook point is available
func (p *Probe) testHookPoint(hook string) bool {
	// For now, use the same logic as BPF features
	// In a real implementation, you'd test specific hook points
	return p.testBPFFeature(hook)
}

// probeResourceLimits detects system resource limits
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
	limits["cpu_count"] = runtime.NumCPU()
	
	info.ResourceLimits = limits
	return nil
}

// PublishCapabilities publishes capability information to NATS
func (p *Probe) PublishCapabilities(ctx context.Context, natsConn interface{}, hostID string) error {
	// This would integrate with the observability system
	// For now, just log the capabilities
	capabilities, err := p.ProbeCapabilities(ctx)
	if err != nil {
		return fmt.Errorf("failed to probe capabilities: %w", err)
	}
	
	// Convert to JSON for logging
	jsonData, err := json.MarshalIndent(capabilities, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal capabilities: %w", err)
	}
	
	fmt.Printf("System Capabilities:\n%s\n", string(jsonData))
	
	// TODO: Publish to NATS via observability system
	return nil
}

// GetCapabilitySummary returns a summary of capabilities
func (p *Probe) GetCapabilitySummary(ctx context.Context) (map[string]interface{}, error) {
	capabilities, err := p.ProbeCapabilities(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to probe capabilities: %w", err)
	}
	
	summary := map[string]interface{}{
		"host_id":        capabilities.HostID,
		"kernel_version": capabilities.KernelVersion,
		"btf_available":  capabilities.BTFAvailable,
		"bpf_features":   len(capabilities.BPFFeatures),
		"hook_points":    len(capabilities.HookPoints),
		"timestamp":      capabilities.Timestamp,
	}
	
	// Count available features
	availableFeatures := 0
	for _, available := range capabilities.BPFFeatures {
		if available {
			availableFeatures++
		}
	}
	summary["available_bpf_features"] = availableFeatures
	
	// Count available hook points
	availableHooks := 0
	for _, available := range capabilities.HookPoints {
		if available {
			availableHooks++
		}
	}
	summary["available_hook_points"] = availableHooks
	
	return summary, nil
}
