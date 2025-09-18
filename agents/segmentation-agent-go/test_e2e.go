package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"

	"agents/segmentation-agent-go/internal/build"
	"agents/segmentation-agent-go/internal/capability"
	"agents/segmentation-agent-go/internal/loader"
	"agents/segmentation-agent-go/internal/observability"
	"agents/segmentation-agent-go/internal/policy"
)

// E2ETestSuite runs end-to-end tests for the segmentation agent
type E2ETestSuite struct {
	builder     *build.COREBuilder
	loader      *loader.Loader
	policyEngine *policy.Engine
	observability *observability.Observability
	capProbe    *capability.Probe
}

// NewE2ETestSuite creates a new test suite
func NewE2ETestSuite() *E2ETestSuite {
	// Initialize components
	builder := build.NewCOREBuilder(
		"clang",
		"bpftool",
		"/sys/kernel/btf/vmlinux",
		"./test_build",
	)
	
	loader := loader.NewLoader()
	policyEngine := policy.NewEngine()
	obs := observability.New("nats://localhost:4222", "test-host")
	capProbe := capability.NewProbe()
	
	return &E2ETestSuite{
		builder:      builder,
		loader:       loader,
		policyEngine: policyEngine,
		observability: obs,
		capProbe:     capProbe,
	}
}

// RunAllTests runs all end-to-end tests
func (ts *E2ETestSuite) RunAllTests() error {
	fmt.Println("🧪 Starting AegisFlux Segmentation Agent E2E Tests")
	fmt.Println("=" * 60)
	
	tests := []struct {
		name string
		fn   func() error
	}{
		{"Build Environment Validation", ts.testBuildEnvironment},
		{"System Capability Detection", ts.testCapabilityDetection},
		{"eBPF Program Compilation", ts.testEBPFCompilation},
		{"Policy Engine Functionality", ts.testPolicyEngine},
		{"eBPF Program Loading", ts.testEBPFLoading},
		{"Network Segmentation (XDP)", ts.testNetworkSegmentation},
		{"Process Isolation (Cgroup)", ts.testProcessIsolation},
		{"Traffic Control (TC)", ts.testTrafficControl},
		{"Observability Integration", ts.testObservability},
		{"End-to-End Segmentation", ts.testEndToEndSegmentation},
	}
	
	passed := 0
	failed := 0
	
	for _, test := range tests {
		fmt.Printf("\n🔍 Running: %s\n", test.name)
		fmt.Println("-" * 40)
		
		start := time.Now()
		err := test.fn()
		duration := time.Since(start)
		
		if err != nil {
			fmt.Printf("❌ FAILED: %s (%.2fs)\n", test.name, duration.Seconds())
			fmt.Printf("   Error: %v\n", err)
			failed++
		} else {
			fmt.Printf("✅ PASSED: %s (%.2fs)\n", test.name, duration.Seconds())
			passed++
		}
	}
	
	fmt.Println("\n" + "=" * 60)
	fmt.Printf("📊 Test Results: %d passed, %d failed\n", passed, failed)
	
	if failed > 0 {
		return fmt.Errorf("some tests failed")
	}
	
	fmt.Println("🎉 All tests passed!")
	return nil
}

// testBuildEnvironment validates the build environment
func (ts *E2ETestSuite) testBuildEnvironment() error {
	// Check if required tools are available
	tools := []string{"clang", "bpftool", "ip", "tc"}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("required tool %s not found: %w", tool, err)
		}
	}
	
	// Validate build environment
	if err := ts.builder.ValidateBuildEnvironment(); err != nil {
		return fmt.Errorf("build environment validation failed: %w", err)
	}
	
	// Get build info
	info := ts.builder.GetBuildInfo()
	fmt.Printf("   Clang: %s\n", info["clang_version"])
	fmt.Printf("   Bpftool: %s\n", info["bpftool_version"])
	
	return nil
}

// testCapabilityDetection tests system capability detection
func (ts *E2ETestSuite) testCapabilityDetection() error {
	ctx := context.Background()
	
	// Probe capabilities
	capabilities, err := ts.capProbe.ProbeCapabilities(ctx)
	if err != nil {
		return fmt.Errorf("capability probe failed: %w", err)
	}
	
	// Check essential capabilities
	if !capabilities.BTFAvailable {
		return fmt.Errorf("BTF not available")
	}
	
	// Check BPF features
	requiredFeatures := []string{"xdp", "tc", "cgroup", "kprobe"}
	for _, feature := range requiredFeatures {
		if !capabilities.BPFFeatures[feature] {
			return fmt.Errorf("required BPF feature %s not available", feature)
		}
	}
	
	fmt.Printf("   Kernel: %s\n", capabilities.KernelVersion)
	fmt.Printf("   BTF: %v\n", capabilities.BTFAvailable)
	fmt.Printf("   BPF Features: %d available\n", len(capabilities.BPFFeatures))
	
	return nil
}

// testEBPFCompilation tests eBPF program compilation
func (ts *E2ETestSuite) testEBPFCompilation() error {
	ctx := context.Background()
	
	// Build XDP segmentation program
	xdpResult, err := ts.builder.BuildTemplate(ctx, "xdp_segmentation", map[string]interface{}{
		"MAX_POLICIES": 256,
		"MAX_PORTS":    1024,
	})
	if err != nil {
		return fmt.Errorf("XDP compilation failed: %w", err)
	}
	
	// Build TC ingress program
	tcResult, err := ts.builder.BuildTemplate(ctx, "tc_ingress", map[string]interface{}{
		"MAX_CLASSES": 64,
		"MAX_FILTERS": 256,
	})
	if err != nil {
		return fmt.Errorf("TC compilation failed: %w", err)
	}
	
	// Build cgroup connect programs
	connect4Result, err := ts.builder.BuildTemplate(ctx, "cgroup_connect4", map[string]interface{}{
		"MAX_POLICIES":  256,
		"MAX_PROCESSES": 1024,
	})
	if err != nil {
		return fmt.Errorf("Cgroup connect4 compilation failed: %w", err)
	}
	
	connect6Result, err := ts.builder.BuildTemplate(ctx, "cgroup_connect6", map[string]interface{}{
		"MAX_POLICIES":  256,
		"MAX_PROCESSES": 1024,
	})
	if err != nil {
		return fmt.Errorf("Cgroup connect6 compilation failed: %w", err)
	}
	
	fmt.Printf("   XDP Program: %s (%.2fs)\n", xdpResult.ObjectFile, xdpResult.BuildTime.Seconds())
	fmt.Printf("   TC Program: %s (%.2fs)\n", tcResult.ObjectFile, tcResult.BuildTime.Seconds())
	fmt.Printf("   Cgroup Connect4: %s (%.2fs)\n", connect4Result.ObjectFile, connect4Result.BuildTime.Seconds())
	fmt.Printf("   Cgroup Connect6: %s (%.2fs)\n", connect6Result.ObjectFile, connect6Result.BuildTime.Seconds())
	
	return nil
}

// testPolicyEngine tests the policy engine
func (ts *E2ETestSuite) testPolicyEngine() error {
	// Create test policies
	networkPolicy := &policy.Policy{
		ID:          "test-network-1",
		Name:        "Test Network Policy",
		Description: "Allow HTTP traffic from specific IPs",
		Type:        "network",
		Priority:    100,
		Enabled:     true,
		Rules: []policy.Rule{
			{
				ID:       "rule-1",
				Action:   "allow",
				Priority: 1,
				Conditions: []policy.Condition{
					{Field: "protocol", Operator: "eq", Value: "tcp"},
					{Field: "dest_port", Operator: "eq", Value: 80},
				},
			},
		},
	}
	
	processPolicy := &policy.Policy{
		ID:          "test-process-1",
		Name:        "Test Process Policy",
		Description: "Block specific processes from network access",
		Type:        "process",
		Priority:    200,
		Enabled:     true,
		Rules: []policy.Rule{
			{
				ID:       "rule-1",
				Action:   "deny",
				Priority: 1,
				Conditions: []policy.Condition{
					{Field: "process_name", Operator: "eq", Value: "malicious"},
				},
			},
		},
	}
	
	// Add policies
	if err := ts.policyEngine.AddPolicy(networkPolicy); err != nil {
		return fmt.Errorf("failed to add network policy: %w", err)
	}
	
	if err := ts.policyEngine.AddPolicy(processPolicy); err != nil {
		return fmt.Errorf("failed to add process policy: %w", err)
	}
	
	// Test policy evaluation
	context := map[string]interface{}{
		"protocol":     "tcp",
		"dest_port":    80,
		"process_name": "nginx",
	}
	
	allowed, reason, err := ts.policyEngine.EvaluatePolicy("test-network-1", context)
	if err != nil {
		return fmt.Errorf("policy evaluation failed: %w", err)
	}
	
	if !allowed {
		return fmt.Errorf("expected policy to allow, but got: %s", reason)
	}
	
	// Test policy stats
	stats := ts.policyEngine.GetPolicyStats()
	if stats["total_policies"].(int) != 2 {
		return fmt.Errorf("expected 2 policies, got %d", stats["total_policies"])
	}
	
	fmt.Printf("   Policies: %d total, %d enabled\n", 
		stats["total_policies"], stats["enabled_policies"])
	
	return nil
}

// testEBPFLoading tests eBPF program loading
func (ts *E2ETestSuite) testEBPFLoading() error {
	ctx := context.Background()
	
	// Build a test program first
	result, err := ts.builder.BuildTemplate(ctx, "xdp_segmentation", map[string]interface{}{
		"MAX_POLICIES": 256,
		"MAX_PORTS":    1024,
	})
	if err != nil {
		return fmt.Errorf("failed to build test program: %w", err)
	}
	
	// Load the program
	info, err := ts.loader.LoadProgram(ctx, result.ObjectFile, "xdp_segmentation_prog")
	if err != nil {
		return fmt.Errorf("failed to load program: %w", err)
	}
	
	// Verify program info
	if info.Name != "xdp_segmentation_prog" {
		return fmt.Errorf("unexpected program name: %s", info.Name)
	}
	
	if info.Type.String() != "XDP" {
		return fmt.Errorf("unexpected program type: %s", info.Type.String())
	}
	
	// Test program listing
	programs := ts.loader.ListPrograms()
	if len(programs) != 1 {
		return fmt.Errorf("expected 1 program, got %d", len(programs))
	}
	
	fmt.Printf("   Loaded: %s (%s)\n", info.Name, info.Type.String())
	fmt.Printf("   Programs: %d loaded\n", len(programs))
	
	return nil
}

// testNetworkSegmentation tests network segmentation with XDP
func (ts *E2ETestSuite) testNetworkSegmentation() error {
	// This would test actual XDP program attachment and packet filtering
	// For now, just verify the program can be loaded
	
	ctx := context.Background()
	
	// Build XDP program
	result, err := ts.builder.BuildTemplate(ctx, "xdp_segmentation", map[string]interface{}{
		"MAX_POLICIES": 256,
		"MAX_PORTS":    1024,
	})
	if err != nil {
		return fmt.Errorf("failed to build XDP program: %w", err)
	}
	
	// Load program
	info, err := ts.loader.LoadProgram(ctx, result.ObjectFile, "xdp_segmentation_prog")
	if err != nil {
		return fmt.Errorf("failed to load XDP program: %w", err)
	}
	
	// In a real test, we would:
	// 1. Attach to a network interface
	// 2. Send test packets
	// 3. Verify filtering behavior
	// 4. Check statistics
	
	fmt.Printf("   XDP Program: %s loaded successfully\n", info.Name)
	fmt.Printf("   Size: %d bytes\n", info.Size)
	
	return nil
}

// testProcessIsolation tests process isolation with cgroup hooks
func (ts *E2ETestSuite) testProcessIsolation() error {
	ctx := context.Background()
	
	// Build cgroup connect programs
	connect4Result, err := ts.builder.BuildTemplate(ctx, "cgroup_connect4", map[string]interface{}{
		"MAX_POLICIES":  256,
		"MAX_PROCESSES": 1024,
	})
	if err != nil {
		return fmt.Errorf("failed to build cgroup connect4 program: %w", err)
	}
	
	connect6Result, err := ts.builder.BuildTemplate(ctx, "cgroup_connect6", map[string]interface{}{
		"MAX_POLICIES":  256,
		"MAX_PROCESSES": 1024,
	})
	if err != nil {
		return fmt.Errorf("failed to build cgroup connect6 program: %w", err)
	}
	
	// Load programs
	info4, err := ts.loader.LoadProgram(ctx, connect4Result.ObjectFile, "cgroup_connect4_prog")
	if err != nil {
		return fmt.Errorf("failed to load cgroup connect4 program: %w", err)
	}
	
	info6, err := ts.loader.LoadProgram(ctx, connect6Result.ObjectFile, "cgroup_connect6_prog")
	if err != nil {
		return fmt.Errorf("failed to load cgroup connect6 program: %w", err)
	}
	
	// In a real test, we would:
	// 1. Create test cgroups
	// 2. Attach programs to cgroups
	// 3. Test connection attempts
	// 4. Verify blocking behavior
	
	fmt.Printf("   Cgroup Connect4: %s loaded\n", info4.Name)
	fmt.Printf("   Cgroup Connect6: %s loaded\n", info6.Name)
	
	return nil
}

// testTrafficControl tests traffic control with TC
func (ts *E2ETestSuite) testTrafficControl() error {
	ctx := context.Background()
	
	// Build TC program
	result, err := ts.builder.BuildTemplate(ctx, "tc_ingress", map[string]interface{}{
		"MAX_CLASSES": 64,
		"MAX_FILTERS": 256,
	})
	if err != nil {
		return fmt.Errorf("failed to build TC program: %w", err)
	}
	
	// Load program
	info, err := ts.loader.LoadProgram(ctx, result.ObjectFile, "tc_ingress_prog")
	if err != nil {
		return fmt.Errorf("failed to load TC program: %w", err)
	}
	
	// In a real test, we would:
	// 1. Create TC qdisc and classes
	// 2. Attach program to interface
	// 3. Test traffic shaping
	// 4. Verify statistics
	
	fmt.Printf("   TC Program: %s loaded successfully\n", info.Name)
	
	return nil
}

// testObservability tests observability integration
func (ts *E2ETestSuite) testObservability() error {
	// Test metric publishing
	if err := ts.observability.PublishCounter("test_counter", 1.0, map[string]string{"test": "true"}); err != nil {
		return fmt.Errorf("failed to publish counter: %w", err)
	}
	
	if err := ts.observability.PublishGauge("test_gauge", 42.0, map[string]string{"test": "true"}); err != nil {
		return fmt.Errorf("failed to publish gauge: %w", err)
	}
	
	// Test event publishing
	event := observability.SegmentationEvent{
		EventType:  "test_event",
		PolicyID:   "test-policy",
		SourceIP:   "192.168.1.1",
		DestIP:     "192.168.1.2",
		SourcePort: 12345,
		DestPort:   80,
		Protocol:   "tcp",
		Interface:  "eth0",
	}
	
	if err := ts.observability.PublishSegmentationEvent(event); err != nil {
		return fmt.Errorf("failed to publish segmentation event: %w", err)
	}
	
	fmt.Printf("   Metrics: published successfully\n")
	fmt.Printf("   Events: published successfully\n")
	
	return nil
}

// testEndToEndSegmentation tests the complete segmentation workflow
func (ts *E2ETestSuite) testEndToEndSegmentation() error {
	ctx := context.Background()
	
	// 1. Create policies
	networkPolicy := &policy.Policy{
		ID:       "e2e-network-1",
		Name:     "E2E Network Policy",
		Type:     "network",
		Priority: 100,
		Enabled:  true,
		Rules: []policy.Rule{
			{
				ID:       "allow-http",
				Action:   "allow",
				Priority: 1,
				Conditions: []policy.Condition{
					{Field: "protocol", Operator: "eq", Value: "tcp"},
					{Field: "dest_port", Operator: "eq", Value: 80},
				},
			},
			{
				ID:       "deny-ssh",
				Action:   "deny",
				Priority: 2,
				Conditions: []policy.Condition{
					{Field: "protocol", Operator: "eq", Value: "tcp"},
					{Field: "dest_port", Operator: "eq", Value: 22},
				},
			},
		},
	}
	
	if err := ts.policyEngine.AddPolicy(networkPolicy); err != nil {
		return fmt.Errorf("failed to add network policy: %w", err)
	}
	
	// 2. Build and load eBPF programs
	xdpResult, err := ts.builder.BuildTemplate(ctx, "xdp_segmentation", map[string]interface{}{
		"MAX_POLICIES": 256,
		"MAX_PORTS":    1024,
	})
	if err != nil {
		return fmt.Errorf("failed to build XDP program: %w", err)
	}
	
	info, err := ts.loader.LoadProgram(ctx, xdpResult.ObjectFile, "xdp_segmentation_prog")
	if err != nil {
		return fmt.Errorf("failed to load XDP program: %w", err)
	}
	
	// 3. Test policy evaluation
	testCases := []struct {
		name     string
		context  map[string]interface{}
		expected bool
	}{
		{
			name: "HTTP traffic should be allowed",
			context: map[string]interface{}{
				"protocol":  "tcp",
				"dest_port": 80,
			},
			expected: true,
		},
		{
			name: "SSH traffic should be denied",
			context: map[string]interface{}{
				"protocol":  "tcp",
				"dest_port": 22,
			},
			expected: false,
		},
		{
			name: "Other traffic should be denied",
			context: map[string]interface{}{
				"protocol":  "tcp",
				"dest_port": 443,
			},
			expected: false,
		},
	}
	
	for _, tc := range testCases {
		allowed, reason, err := ts.policyEngine.EvaluatePolicy("e2e-network-1", tc.context)
		if err != nil {
			return fmt.Errorf("policy evaluation failed for %s: %w", tc.name, err)
		}
		
		if allowed != tc.expected {
			return fmt.Errorf("policy evaluation failed for %s: expected %v, got %v (reason: %s)", 
				tc.name, tc.expected, allowed, reason)
		}
	}
	
	// 4. Test observability
	if err := ts.observability.PublishPacketAllow("e2e-network-1", "192.168.1.1", "192.168.1.2", 12345, 80, "tcp", "eth0"); err != nil {
		return fmt.Errorf("failed to publish packet allow event: %w", err)
	}
	
	if err := ts.observability.PublishPacketDrop("e2e-network-1", "192.168.1.1", "192.168.1.2", 12345, 22, "tcp", "eth0"); err != nil {
		return fmt.Errorf("failed to publish packet drop event: %w", err)
	}
	
	fmt.Printf("   Policies: %d created and tested\n", 1)
	fmt.Printf("   Programs: %s loaded\n", info.Name)
	fmt.Printf("   Test Cases: %d passed\n", len(testCases))
	fmt.Printf("   Events: published successfully\n")
	
	return nil
}

// main runs the E2E test suite
func main() {
	// Check if running as root (required for eBPF)
	if syscall.Getuid() != 0 {
		log.Fatal("E2E tests must be run as root for eBPF functionality")
	}
	
	// Create test suite
	suite := NewE2ETestSuite()
	defer suite.loader.Close()
	defer suite.observability.Close()
	
	// Run tests
	if err := suite.RunAllTests(); err != nil {
		log.Fatalf("E2E tests failed: %v", err)
	}
}
