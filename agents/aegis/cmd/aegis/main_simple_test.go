package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"agents/aegis/internal/ebpf"
	"agents/aegis/internal/telemetry"
	"agents/aegis/pkg/models"
)

func main() {
	// Define flags
	var (
		policyFile = flag.String("policy", "", "Path to policy JSON file")
		verbose    = flag.Bool("verbose", false, "Enable verbose logging")
	)
	
	flag.Parse()
	
	// Set up logging
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	
	if *policyFile == "" {
		log.Fatal("Policy file is required. Use -policy flag.")
	}
	
	log.Printf("Starting Aegis Agent - Simple Policy Test (No Verification)")
	log.Printf("Policy File: %s", *policyFile)
	
	// Generate IDs
	hostID := generateHostID()
	agentID := generateAgentID()
	
	log.Printf("Host ID: %s, Agent ID: %s", hostID, agentID)
	
	// Initialize event emitter
	eventEmitter := telemetry.NewEventEmitter(hostID, agentID)
	defer eventEmitter.Close()
	
	// Initialize eBPF loader (dry-run = false for real application)
	loader := ebpf.NewLoader(nil, eventEmitter, false) // No verifier for this test
	defer loader.Close()
	
	// Load policy from file
	assignment, err := loadPolicyFromFile(*policyFile)
	if err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}
	
	log.Printf("Loaded policy: %s (ID: %s)", assignment.PolicyID, assignment.ID)
	
	// Start telemetry event processing
	go processTelemetryEvents(eventEmitter)
	
	// Apply the policy (real application, no verification)
	ctx := context.Background()
	result := loader.LoadAssignment(ctx, assignment)
	
	if result.Success {
		log.Printf("✅ Policy applied successfully!")
		log.Printf("Changes: %v", result.Changes)
		if len(result.Warnings) > 0 {
			log.Printf("Warnings: %v", result.Warnings)
		}
		log.Printf("Duration: %v", result.Duration)
		
		// Show what would be applied
		log.Printf("📋 Policy Details:")
		log.Printf("  - Assignment ID: %s", assignment.ID)
		log.Printf("  - Policy ID: %s", assignment.PolicyID)
		log.Printf("  - Version: %s", assignment.Version)
		log.Printf("  - Priority: %d", assignment.Priority)
		log.Printf("  - Dry Run: %t", assignment.DryRun)
		
		// Decode and show policy content
		if len(assignment.Bundle.Content) > 0 {
			policyData, err := decodePolicyContent(assignment.Bundle.Content)
			if err == nil {
				log.Printf("📊 Policy Content:")
				log.Printf("  - Egress Policies: %d", len(policyData.EgressPolicies))
				log.Printf("  - Ingress Policies: %d", len(policyData.IngressPolicies))
				log.Printf("  - Policy Edges: %d", len(policyData.PolicyEdges))
				log.Printf("  - Allow CIDRs: %d", len(policyData.AllowCIDRs))
			}
		}
		
	} else {
		log.Printf("❌ Policy application failed!")
		log.Printf("Errors: %v", result.Errors)
		log.Printf("Duration: %v", result.Duration)
		os.Exit(1)
	}
	
	// Keep running to maintain the policy
	log.Printf("Policy is now active. Press Ctrl+C to stop.")
	select {}
}

// PolicyData represents parsed policy content
type PolicyData struct {
	EgressPolicies  []EgressPolicy  `json:"egress_policies"`
	IngressPolicies []IngressPolicy `json:"ingress_policies"`
	PolicyEdges     []PolicyEdge    `json:"policy_edges"`
	AllowCIDRs      []AllowCIDR     `json:"allow_cidrs"`
	Metadata        map[string]any  `json:"metadata"`
}

// EgressPolicy represents an egress policy
type EgressPolicy struct {
	ID          uint32 `json:"id"`
	ProcessUID  uint32 `json:"process_uid"`
	ProcessGID  uint32 `json:"process_gid"`
	AllowedPorts []uint16 `json:"allowed_ports"`
	BlockedPorts []uint16 `json:"blocked_ports"`
	Action      uint8  `json:"action"`
	Priority    uint8  `json:"priority"`
}

// IngressPolicy represents an ingress policy
type IngressPolicy struct {
	ID          uint32 `json:"id"`
	SrcIP       uint32 `json:"src_ip"`
	SrcMask     uint32 `json:"src_mask"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    uint8  `json:"protocol"`
	Action      uint8  `json:"action"`
	Priority    uint8  `json:"priority"`
}

// PolicyEdge represents a network segmentation policy edge
type PolicyEdge struct {
	ID          uint32 `json:"id"`
	SrcIP       uint32 `json:"src_ip"`
	DstIP       uint32 `json:"dst_ip"`
	SrcMask     uint32 `json:"src_mask"`
	DstMask     uint32 `json:"dst_mask"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    uint8  `json:"protocol"`
	Action      uint8  `json:"action"`
	Priority    uint8  `json:"priority"`
	ProcessUID  uint32 `json:"process_uid"`
	ProcessGID  uint32 `json:"process_gid"`
	Timestamp   uint64 `json:"timestamp"`
}

// AllowCIDR represents a CIDR allowlist entry
type AllowCIDR struct {
	PrefixLen uint32 `json:"prefix_len"`
	IP        uint32 `json:"ip"`
	Action    uint8  `json:"action"`
	Priority  uint8  `json:"priority"`
	Timestamp uint64 `json:"timestamp"`
}

// loadPolicyFromFile loads a policy from a JSON file
func loadPolicyFromFile(filename string) (*models.Assignment, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	
	var assignment models.Assignment
	if err := json.Unmarshal(data, &assignment); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}
	
	// Set some defaults if not provided
	if assignment.ID == "" {
		assignment.ID = fmt.Sprintf("policy-%d", time.Now().Unix())
	}
	if assignment.PolicyID == "" {
		assignment.PolicyID = "example-policy"
	}
	if assignment.Version == "" {
		assignment.Version = "1.0.0"
	}
	if assignment.CreatedAt.IsZero() {
		assignment.CreatedAt = time.Now()
	}
	
	return &assignment, nil
}

// decodePolicyContent decodes the base64 policy content
func decodePolicyContent(content []byte) (*PolicyData, error) {
	// For this test, we'll assume the content is already JSON
	var policyData PolicyData
	if err := json.Unmarshal(content, &policyData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy content: %w", err)
	}
	return &policyData, nil
}

// processTelemetryEvents processes telemetry events
func processTelemetryEvents(eventEmitter *telemetry.EventEmitter) {
	for event := range eventEmitter.GetEvents() {
		// Process event (e.g., send to NATS, log, etc.)
		eventJSON, err := event.ToJSON()
		if err != nil {
			log.Printf("Failed to marshal event: %v", err)
			continue
		}
		
		log.Printf("📊 Telemetry: %s", string(eventJSON))
	}
}

// generateHostID generates a host ID
func generateHostID() string {
	// Try environment variable first
	if hostID := os.Getenv("AGENT_HOST_ID"); hostID != "" {
		return hostID
	}
	
	// Try machine ID
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		if len(data) > 0 {
			return string(data[:32]) // Use first 32 characters
		}
	}
	
	// Fallback to hostname
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	
	// Final fallback
	return fmt.Sprintf("host-%d", time.Now().Unix())
}

// generateAgentID generates an agent ID
func generateAgentID() string {
	// Try environment variable first
	if agentID := os.Getenv("AGENT_ID"); agentID != "" {
		return agentID
	}
	
	// Generate based on host ID and timestamp
	hostID := generateHostID()
	return fmt.Sprintf("agent-%s-%d", hostID, time.Now().Unix())
}

