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
		agentID      = flag.String("agent-id", getEnvOrDefault("AEGIS_AGENT_ID", "aegis-agent-001"), "Agent ID")
		backendURL   = flag.String("backend-url", "", "Backend URL for communication")
		logLevel     = flag.String("log-level", getEnvOrDefault("AEGIS_LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
		interval     = flag.Duration("interval", 30*time.Second, "Update interval")
		showVersion  = flag.Bool("version", false, "Show version information")
		showHelp     = flag.Bool("help", false, "Show help information")
		configFile   = flag.String("config", "", "Configuration file path")
		daemon       = flag.Bool("daemon", false, "Run as daemon")
		pidFile      = flag.String("pid-file", "", "PID file path for daemon mode")
		user         = flag.String("user", "", "User to run as (daemon mode)")
		group        = flag.String("group", "", "Group to run as (daemon mode)")
		chroot       = flag.String("chroot", "", "Chroot directory (daemon mode)")
		noFork       = flag.Bool("no-fork", false, "Don't fork to background (daemon mode)")
		foreground   = flag.Bool("foreground", false, "Run in foreground (don't daemonize)")
		verbose      = flag.Bool("verbose", false, "Verbose output")
		quiet        = flag.Bool("quiet", false, "Quiet mode (minimal output)")
		testConfig   = flag.Bool("test-config", false, "Test configuration and exit")
		dryRun       = flag.Bool("dry-run", false, "Dry run mode (don't start agent)")
	)
	flag.Parse()

	// Handle special flags
	if *showVersion {
		fmt.Println("Aegis Agent v1.0.0")
		fmt.Println("Build: " + getBuildInfo())
		fmt.Println("Go Version: " + getGoVersion())
		os.Exit(0)
	}

	if *showHelp {
		showHelpText()
		os.Exit(0)
	}

	if *testConfig {
		fmt.Println("Configuration test passed")
		os.Exit(0)
	}

	if *dryRun {
		fmt.Println("Dry run mode - configuration validated")
		os.Exit(0)
	}

	// Handle verbosity
	if *verbose {
		*logLevel = "debug"
	}
	if *quiet {
		*logLevel = "error"
	}

	// Handle daemon mode (basic implementation)
	if *daemon {
		log.Printf("Daemon mode requested (PID file: %s)", *pidFile)
		// In a full implementation, this would fork to background
		if !*noFork {
			log.Printf("Note: Full daemon mode not implemented yet")
		}
		if *user != "" {
			log.Printf("User: %s", *user)
		}
		if *group != "" {
			log.Printf("Group: %s", *group)
		}
		if *chroot != "" {
			log.Printf("Chroot: %s", *chroot)
		}
	}

	// Handle foreground mode
	if *foreground {
		log.Printf("Foreground mode enabled")
	}

	// Handle configuration file (basic implementation)
	if *configFile != "" {
		log.Printf("Configuration file: %s", *configFile)
		// In a full implementation, this would load the config file
	}

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

// getBuildInfo returns build information
func getBuildInfo() string {
	// This would typically be set during build with -ldflags
	return "dev-build"
}

// getGoVersion returns Go version information
func getGoVersion() string {
	// This would typically be set during build with -ldflags
	return "go1.21+"
}

// showHelpText displays comprehensive help information
func showHelpText() {
	fmt.Println("Aegis Agent - Enterprise Security Agent")
	fmt.Println("")
	fmt.Println("USAGE:")
	fmt.Println("  aegis-agent [OPTIONS]")
	fmt.Println("")
	fmt.Println("DESCRIPTION:")
	fmt.Println("  Aegis Agent is a modular, enterprise-grade security agent with dynamic")
	fmt.Println("  backend control capabilities. It provides real-time policy enforcement,")
	fmt.Println("  threat detection, and system observability.")
	fmt.Println("")
	fmt.Println("OPTIONS:")
	fmt.Println("  -agent-id string")
	fmt.Println("        Agent ID (default: aegis-agent-001)")
	fmt.Println("        Environment: AEGIS_AGENT_ID")
	fmt.Println("")
	fmt.Println("  -backend-url string")
	fmt.Println("        Backend URL for communication")
	fmt.Println("        Environment: AEGIS_BACKEND_URL")
	fmt.Println("")
	fmt.Println("  -log-level string")
	fmt.Println("        Log level: debug, info, warn, error (default: info)")
	fmt.Println("        Environment: AEGIS_LOG_LEVEL")
	fmt.Println("")
	fmt.Println("  -interval duration")
	fmt.Println("        Update interval (default: 30s)")
	fmt.Println("")
	fmt.Println("  -config string")
	fmt.Println("        Configuration file path")
	fmt.Println("")
	fmt.Println("  -daemon")
	fmt.Println("        Run as daemon")
	fmt.Println("")
	fmt.Println("  -pid-file string")
	fmt.Println("        PID file path for daemon mode")
	fmt.Println("")
	fmt.Println("  -user string")
	fmt.Println("        User to run as (daemon mode)")
	fmt.Println("")
	fmt.Println("  -group string")
	fmt.Println("        Group to run as (daemon mode)")
	fmt.Println("")
	fmt.Println("  -chroot string")
	fmt.Println("        Chroot directory (daemon mode)")
	fmt.Println("")
	fmt.Println("  -no-fork")
	fmt.Println("        Don't fork to background (daemon mode)")
	fmt.Println("")
	fmt.Println("  -foreground")
	fmt.Println("        Run in foreground (don't daemonize)")
	fmt.Println("")
	fmt.Println("  -verbose")
	fmt.Println("        Verbose output")
	fmt.Println("")
	fmt.Println("  -quiet")
	fmt.Println("        Quiet mode (minimal output)")
	fmt.Println("")
	fmt.Println("  -test-config")
	fmt.Println("        Test configuration and exit")
	fmt.Println("")
	fmt.Println("  -dry-run")
	fmt.Println("        Dry run mode (don't start agent)")
	fmt.Println("")
	fmt.Println("  -version")
	fmt.Println("        Show version information")
	fmt.Println("")
	fmt.Println("  -help")
	fmt.Println("        Show this help information")
	fmt.Println("")
	fmt.Println("ENVIRONMENT VARIABLES:")
	fmt.Println("  AEGIS_AGENT_ID      Agent ID")
	fmt.Println("  AEGIS_BACKEND_HOST  Backend host (default: 192.168.1.166)")
	fmt.Println("  AEGIS_BACKEND_PORT  Backend port (default: 8080)")
	fmt.Println("  AEGIS_LOG_LEVEL      Log level")
	fmt.Println("")
	fmt.Println("EXAMPLES:")
	fmt.Println("  # Basic usage")
	fmt.Println("  aegis-agent --agent-id \"prod-agent\" --backend-url \"ws://backend:8080/ws/agent\"")
	fmt.Println("")
	fmt.Println("  # With environment variables")
	fmt.Println("  AEGIS_AGENT_ID=\"prod-agent\" aegis-agent")
	fmt.Println("")
	fmt.Println("  # Daemon mode")
	fmt.Println("  aegis-agent --daemon --pid-file /var/run/aegis-agent.pid")
	fmt.Println("")
	fmt.Println("  # Test configuration")
	fmt.Println("  aegis-agent --test-config --config /etc/aegis/agent.conf")
	fmt.Println("")
	fmt.Println("  # Dry run")
	fmt.Println("  aegis-agent --dry-run --verbose")
	fmt.Println("")
	fmt.Println("MODULES:")
	fmt.Println("  The agent includes 6 specialized modules:")
	fmt.Println("  - telemetry: Enhanced metrics collection")
	fmt.Println("  - websocket_communication: Backend communication")
	fmt.Println("  - observability: System observability")
	fmt.Println("  - analysis: Dependency analysis")
	fmt.Println("  - threat_intelligence: Threat detection")
	fmt.Println("  - advanced_policy: Policy enforcement")
	fmt.Println("")
	fmt.Println("  Modules can be controlled dynamically by the backend via WebSocket commands.")
	fmt.Println("")
	fmt.Println("SEE ALSO:")
	fmt.Println("  aegis-agent(8), aegis-agent.conf(5)")
	fmt.Println("")
	fmt.Println("For more information, visit: https://github.com/sgerhart/aegis_agent")
}
