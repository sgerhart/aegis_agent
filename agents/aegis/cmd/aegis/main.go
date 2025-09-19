package main

import (
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
		dryRun     = flag.Bool("dry-run", false, "Enable dry-run mode (no actual policy application)")
		mtls       = flag.Bool("mtls", false, "Enable mTLS for registry communication")
		trustStore = flag.String("truststore", "/etc/aegis/truststore.json", "Path to trust store file")
		hostID     = flag.String("host-id", "", "Host ID (overrides environment variable)")
		agentID    = flag.String("agent-id", "", "Agent ID")
		verbose    = flag.Bool("verbose", false, "Enable verbose logging")
	)
	
	flag.Parse()
	
	// Check environment variables for flag overrides
	if os.Getenv("AEGIS_DRY_RUN") == "true" {
		*dryRun = true
	}
	if os.Getenv("AEGIS_MTLS") == "true" {
		*mtls = true
	}
	if trustStoreEnv := os.Getenv("AEGIS_TRUSTSTORE"); trustStoreEnv != "" {
		*trustStore = trustStoreEnv
	}
	if hostIDEnv := os.Getenv("AGENT_HOST_ID"); hostIDEnv != "" {
		*hostID = hostIDEnv
	}
	if agentIDEnv := os.Getenv("AGENT_ID"); agentIDEnv != "" {
		*agentID = agentIDEnv
	}
	if verboseEnv := os.Getenv("AEGIS_VERBOSE"); verboseEnv == "true" {
		*verbose = true
	}
	
	// Set up logging
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	
	log.Printf("Starting Aegis Agent (dry-run: %v, mTLS: %v, truststore: %s)", 
		*dryRun, *mtls, *trustStore)
	
	// Initialize components
	if err := initializeAgent(*hostID, *agentID, *trustStore, *dryRun, *mtls); err != nil {
		log.Fatalf("Failed to initialize agent: %v", err)
	}
	
	log.Println("Aegis Agent started successfully")
	
	// Keep running
	select {}
}

// initializeAgent initializes the agent with all required components
func initializeAgent(hostID, agentID, trustStorePath string, dryRun, mtls bool) error {
	// Generate host ID if not provided
	if hostID == "" {
		hostID = generateHostID()
	}
	
	// Generate agent ID if not provided
	if agentID == "" {
		agentID = generateAgentID()
	}
	
	log.Printf("Host ID: %s, Agent ID: %s", hostID, agentID)
	
	// Initialize trust store manager
	trustMgr, err := crypto.NewTrustStoreManager(trustStorePath)
	if err != nil {
		return fmt.Errorf("failed to initialize trust store: %w", err)
	}
	
	// Initialize event emitter
	eventEmitter := telemetry.NewEventEmitter(hostID, agentID)
	defer eventEmitter.Close()
	
	// Initialize verifier
	verifier := trustMgr.GetVerifier()
	
	// Initialize eBPF loader
	loader := ebpf.NewLoader(verifier, eventEmitter, dryRun)
	defer loader.Close()
	
	// Start telemetry event processing
	go processTelemetryEvents(eventEmitter)
	
	// Start TTL checker (with empty assignments for now)
	loader.StartTTLChecker([]*models.Assignment{})
	
	// Emit startup event
	eventEmitter.EmitCounter("agent_started", 1, "count", map[string]string{
		"host_id":    hostID,
		"agent_id":   agentID,
		"dry_run":    fmt.Sprintf("%v", dryRun),
		"mtls":       fmt.Sprintf("%v", mtls),
		"truststore": trustStorePath,
	})
	
	log.Printf("Agent initialized successfully (dry-run: %v, mTLS: %v)", dryRun, mtls)
	
	return nil
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
		
		log.Printf("Telemetry event: %s", string(eventJSON))
		
		// Here you would typically send to NATS or other telemetry systems
		// For now, we'll just log it
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
