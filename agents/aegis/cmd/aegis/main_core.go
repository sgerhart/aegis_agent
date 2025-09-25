package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agents/aegis/internal/core"
)

func main() {
	// Parse command line flags
	var (
		agentID    = flag.String("agent-id", getEnvOrDefault("AEGIS_AGENT_ID", "aegis-agent-001"), "Agent ID")
		backendURL = flag.String("backend-url", "", "Backend URL for communication")
		logLevel   = flag.String("log-level", getEnvOrDefault("AEGIS_LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
		interval   = flag.Duration("interval", 30*time.Second, "Update interval")
	)
	flag.Parse()

	// Build backend URL from environment variables if not provided via flag
	if *backendURL == "" {
		backendHost := getEnvOrDefault("AEGIS_BACKEND_HOST", "192.168.1.166")
		backendPort := getEnvOrDefault("AEGIS_BACKEND_PORT", "8080")
		*backendURL = fmt.Sprintf("ws://%s:%s/ws/agent", backendHost, backendPort)
	}

	// Create core agent configuration
	config := &core.Config{
		AgentID:       *agentID,
		BackendURL:    *backendURL,
		LogLevel:      *logLevel,
		UpdateInterval: *interval,
		EnabledModules: []string{"telemetry", "websocket_communication", "observability"},
		Metadata:      make(map[string]interface{}),
	}

	// Create and start the agent
	agent, err := core.NewAgent(config)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	// Start the agent
	if err := agent.Start(); err != nil {
		log.Fatalf("Failed to start agent: %v", err)
	}

	log.Printf("Aegis Core Agent started successfully (ID: %s)", *agentID)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	log.Printf("Shutdown signal received, stopping agent...")

	// Stop the agent
	if err := agent.Stop(); err != nil {
		log.Printf("Error stopping agent: %v", err)
		os.Exit(1)
	}

	log.Printf("Agent stopped successfully")
}

// getEnvOrDefault returns the value of an environment variable or a default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
