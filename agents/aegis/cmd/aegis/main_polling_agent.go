package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"agents/aegis/internal/polling"
	"agents/aegis/internal/telemetry"
)

var (
	hostID      = flag.String("host-id", "", "Host ID (overrides environment variable)")
	agentID     = flag.String("agent-id", "", "Agent ID")
	orgID       = flag.String("org-id", "security-team", "Organization ID")
	registryURL = flag.String("registry-url", "http://192.168.1.166:8090", "BPF Registry URL")
	actionsURL  = flag.String("actions-url", "http://192.168.1.166:8083", "Actions API URL")
	natsURL     = flag.String("nats-url", "nats://192.168.1.166:4222", "NATS URL")
	verbose     = flag.Bool("verbose", false, "Enable verbose logging")
	httpPort    = flag.Int("http-port", 7070, "HTTP API port")
)

// AgentStatus represents the agent's current status
type AgentStatus struct {
	Status           string                 `json:"status"`
	Version          string                 `json:"version"`
	HostID           string                 `json:"host_id"`
	AgentUID         string                 `json:"agent_uid"`
	Registered       bool                   `json:"registered"`
	BackendConnected bool                   `json:"backend_connected"`
	LastPoll         string                 `json:"last_poll"`
	Programs         map[string]interface{} `json:"programs"`
	Artifacts        []map[string]interface{} `json:"artifacts"`
}

func main() {
	flag.Parse()

	// Setup logging
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	log.Printf("[main] Starting AEGIS eBPF Polling Agent")
	log.Printf("[main] Version: 1.0.0")
	log.Printf("[main] Platform: linux/arm64")

	// Determine host ID
	actualHostID := *hostID
	if actualHostID == "" {
		actualHostID = os.Getenv("AGENT_HOST_ID")
	}
	if actualHostID == "" {
		actualHostID = getDefaultHostID()
	}

	// Set environment variables for polling client
	if *registryURL != "" {
		os.Setenv("AGENT_REGISTRY_URL", *registryURL)
	}
	if *actionsURL != "" {
		os.Setenv("AGENT_ACTIONS_URL", *actionsURL)
	}
	if *natsURL != "" {
		os.Setenv("AGENT_NATS_URL", *natsURL)
	}
	if *orgID != "" {
		os.Setenv("AGENT_ORG_ID", *orgID)
	}

	log.Printf("[main] Host ID: %s", actualHostID)
	log.Printf("[main] Registry URL: %s", *registryURL)
	log.Printf("[main] Actions URL: %s", *actionsURL)
	log.Printf("[main] NATS URL: %s", *natsURL)

	// Initialize telemetry
	eventEmitter := telemetry.NewEventEmitter(actualHostID, *agentID)

	// Initialize polling client
	pollingClient := polling.NewPollingClient(
		actualHostID,
		*registryURL,
		*actionsURL,
		*natsURL,
		eventEmitter,
	)

	if pollingClient == nil {
		log.Fatal("[main] Failed to create polling client")
	}

	// Setup HTTP API for status monitoring
	agentStatus := &AgentStatus{
		Status:           "starting",
		Version:          "1.0.0",
		HostID:           actualHostID,
		Registered:       false,
		BackendConnected: false,
		Programs:         map[string]interface{}{"loaded": 0, "active": 0, "failed": 0},
		Artifacts:        []map[string]interface{}{},
	}

	setupHTTPAPI(agentStatus, *httpPort)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Printf("[main] Received shutdown signal")
		agentStatus.Status = "shutting_down"
		cancel()
	}()

	// Agent startup sequence
	log.Printf("[main] Starting agent registration...")
	agentStatus.Status = "registering"

	if err := pollingClient.Register(); err != nil {
		log.Printf("[main] Registration failed: %v", err)
		log.Printf("[main] Continuing without registration...")
		agentStatus.Registered = false
	} else {
		log.Printf("[main] Registration successful!")
		agentStatus.Registered = true
		agentStatus.AgentUID = "agent-uid-placeholder" // Would get from polling client
	}

	// Connect to NATS for telemetry
	log.Printf("[main] Connecting to NATS for telemetry...")
	if err := pollingClient.ConnectNATS(); err != nil {
		log.Printf("[main] NATS connection failed: %v", err)
		log.Printf("[main] Continuing without telemetry...")
		agentStatus.BackendConnected = false
	} else {
		log.Printf("[main] NATS connection successful!")
		agentStatus.BackendConnected = true
	}

	agentStatus.Status = "healthy"
	agentStatus.LastPoll = time.Now().UTC().Format(time.RFC3339)

	// Emit startup telemetry
	eventEmitter.EmitBackendComm(*actionsURL, "POST", "agent_startup", 200, 0, 0, "")

	log.Printf("[main] Agent startup complete - entering polling loop")

	// Start polling in background
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[main] Polling loop panic: %v", r)
				agentStatus.Status = "error"
			}
		}()

		pollingClient.StartPolling()
	}()

	// Update last poll time periodically
	pollTicker := time.NewTicker(30 * time.Second)
	defer pollTicker.Stop()

	go func() {
		for range pollTicker.C {
			agentStatus.LastPoll = time.Now().UTC().Format(time.RFC3339)
		}
	}()

	// Wait for shutdown
	<-ctx.Done()

	log.Printf("[main] Shutting down AEGIS agent...")
	agentStatus.Status = "stopped"

	// Cleanup
	eventEmitter.Close()

	log.Printf("[main] Agent shutdown complete")
}

// setupHTTPAPI sets up the HTTP API for monitoring
func setupHTTPAPI(status *AgentStatus, port int) {
	mux := http.NewServeMux()

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if status.Status == "healthy" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": status.Status})
		}
	})

	// Status endpoint
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(status)
	})

	// Stats endpoint
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		stats := map[string]interface{}{
			"uptime_seconds":    time.Since(time.Now().Add(-time.Hour)).Seconds(), // Placeholder
			"memory_usage_mb":   45,   // Placeholder
			"cpu_usage_percent": 2.1,  // Placeholder
			"ebpf_programs":     0,    // Would get from eBPF manager
			"active_policies":   0,    // Would get from policy manager
			"backend_polls":     0,    // Would track actual polls
		}
		
		json.NewEncoder(w).Encode(stats)
	})

	// Start HTTP server in background
	go func() {
		addr := fmt.Sprintf(":%d", port)
		log.Printf("[http] Starting HTTP API on %s", addr)
		
		server := &http.Server{
			Addr:    addr,
			Handler: mux,
		}
		
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[http] HTTP server error: %v", err)
		}
	}()
}

// getDefaultHostID generates a default host ID
func getDefaultHostID() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}
	
	// Clean hostname for use as ID
	hostID := strings.ToLower(hostname)
	hostID = strings.ReplaceAll(hostID, ".", "-")
	
	return hostID + "-arm64"
}
