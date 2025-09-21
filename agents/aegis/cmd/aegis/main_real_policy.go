package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"agents/aegis/internal/crypto"
	"agents/aegis/internal/ebpf"
	"agents/aegis/internal/telemetry"
	"agents/aegis/pkg/models"
)

func main() {
	// Define flags
	var (
		trustStore = flag.String("truststore", "/etc/aegis/truststore.json", "Path to trust store file")
		hostID     = flag.String("host-id", "", "Host ID")
		agentID    = flag.String("agent-id", "", "Agent ID")
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
	
	log.Printf("Starting Aegis Agent with Real Policy Application")
	log.Printf("Trust Store: %s", *trustStore)
	log.Printf("Policy File: %s", *policyFile)
	
	// Generate host ID if not provided
	if *hostID == "" {
		*hostID = generateHostID()
	}
	
	// Generate agent ID if not provided
	if *agentID == "" {
		*agentID = generateAgentID()
	}
	
	log.Printf("Host ID: %s, Agent ID: %s", *hostID, *agentID)
	
	// Initialize trust store manager
	trustMgr, err := crypto.NewTrustStoreManager(*trustStore)
	if err != nil {
		log.Fatalf("Failed to initialize trust store: %v", err)
	}
	
	// Initialize event emitter
	eventEmitter := telemetry.NewEventEmitter(*hostID, *agentID)
	defer eventEmitter.Close()
	
	// Initialize verifier
	verifier := trustMgr.GetVerifier()
	
	// Initialize eBPF loader (NOT in dry-run mode)
	loader := ebpf.NewLoader(verifier, eventEmitter, false) // dryRun = false
	defer loader.Close()
	
	// Load policy from file
	assignment, err := loadPolicyFromFile(*policyFile)
	if err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}
	
	log.Printf("Loaded policy: %s (ID: %s)", assignment.PolicyID, assignment.ID)
	
	// Start telemetry event processing
	go processTelemetryEvents(eventEmitter)
	
	// Apply the policy (real application, not dry-run)
	ctx := context.Background()
	result := loader.LoadAssignment(ctx, assignment)
	
	if result.Success {
		log.Printf("✅ Policy applied successfully!")
		log.Printf("Changes: %v", result.Changes)
		if len(result.Warnings) > 0 {
			log.Printf("Warnings: %v", result.Warnings)
		}
		log.Printf("Duration: %v", result.Duration)
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

