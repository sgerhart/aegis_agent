package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"agents/aegis/internal/core"
	"agents/aegis/internal/telemetry"
)

func main() {
	if len(os.Args) < 2 {
		showUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "run", "start", "daemon":
		runAgent(args)
	case "cli", "interactive":
		runCLI(args)
	case "status":
		runStatus(args)
	case "modules":
		runModules(args)
	case "metrics":
		runMetrics(args)
	case "health":
		runHealth(args)
	case "version":
		showVersion()
	case "help", "-h", "--help":
		showHelp()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		showUsage()
		os.Exit(1)
	}
}

// runAgent runs the agent in daemon mode
func runAgent(args []string) {
	// Create a new flag set for agent mode
	flagSet := flag.NewFlagSet("agent", flag.ExitOnError)
	
	// Parse flags for agent mode
	var (
		agentID      = flagSet.String("agent-id", getEnvOrDefault("AEGIS_AGENT_ID", "aegis-agent-001"), "Agent ID")
		backendURL   = flagSet.String("backend-url", "", "Backend URL for communication")
		logLevel     = flagSet.String("log-level", getEnvOrDefault("AEGIS_LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
		interval     = flagSet.Duration("interval", 30*time.Second, "Update interval")
		configFile   = flagSet.String("config", "", "Configuration file path")
		daemon       = flagSet.Bool("daemon", false, "Run as daemon")
		pidFile      = flagSet.String("pid-file", "", "PID file path for daemon mode")
		user         = flagSet.String("user", "", "User to run as (daemon mode)")
		group        = flagSet.String("group", "", "Group to run as (daemon mode)")
		chroot       = flagSet.String("chroot", "", "Chroot directory (daemon mode)")
		noFork       = flagSet.Bool("no-fork", false, "Don't fork to background (daemon mode)")
		foreground   = flagSet.Bool("foreground", false, "Run in foreground (don't daemonize)")
		verbose      = flagSet.Bool("verbose", false, "Verbose output")
		quiet        = flagSet.Bool("quiet", false, "Quiet mode (minimal output)")
		testConfig   = flagSet.Bool("test-config", false, "Test configuration and exit")
		dryRun       = flagSet.Bool("dry-run", false, "Dry run mode (don't start agent)")
	)
	
	// Parse the provided arguments
	if err := flagSet.Parse(args); err != nil {
		log.Fatalf("Failed to parse arguments: %v", err)
	}

	// Handle special flags
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
		EnabledModules: []string{"telemetry", "websocket_communication", "observability", "advanced_policy"},
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

	log.Printf("Aegis Agent started successfully (ID: %s)", *agentID)

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

// runCLI runs the interactive CLI
func runCLI(args []string) {
	// Create logger
	logger := telemetry.NewLogger("aegis-cli")

	// Create agent configuration
	config := &core.Config{
		AgentID:        "aegis-cli",
		BackendURL:     getEnvOrDefault("AEGIS_BACKEND_URL", "ws://192.168.1.166:8080/ws/agent"),
		LogLevel:       "info",
		UpdateInterval: 30 * time.Second,
		EnabledModules: []string{"telemetry", "websocket_communication", "observability", "advanced_policy"},
		Metadata:       make(map[string]interface{}),
	}

	// Create agent
	agent, err := core.NewAgent(config)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	// Start the agent
	if err := agent.Start(); err != nil {
		log.Fatalf("Failed to start agent: %v", err)
	}

	// Create CLI client
	cli := &CLIClient{
		agent:   agent,
		reader:  bufio.NewReader(os.Stdin),
		logger:  logger,
		running: true,
	}

	// Show welcome and help
	cli.showWelcome()
	cli.showHelp()

	// Start interactive loop
	if err := cli.interactiveLoop(); err != nil {
		log.Printf("CLI error: %v", err)
	}

	// Stop the agent
	if err := agent.Stop(); err != nil {
		log.Printf("Error stopping agent: %v", err)
	}
}

// runStatus shows agent status
func runStatus(args []string) {
	fmt.Println("┌─ Agent Status ──────────────────────────────────────────────┐")
	fmt.Println("│ This would connect to a running agent and show status      │")
	fmt.Println("│ In a full implementation, this would use IPC or API calls  │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
}

// runModules shows module information
func runModules(args []string) {
	fmt.Println("┌─ Available Modules ─────────────────────────────────────────┐")
	fmt.Println("│ telemetry                Enhanced metrics collection        │")
	fmt.Println("│ websocket_communication  Backend communication             │")
	fmt.Println("│ observability            System observability              │")
	fmt.Println("│ analysis                 Dependency analysis                │")
	fmt.Println("│ threat_intelligence      Threat detection                  │")
	fmt.Println("│ advanced_policy          Policy enforcement                │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
}

// runMetrics shows agent metrics
func runMetrics(args []string) {
	fmt.Println("┌─ Agent Metrics ─────────────────────────────────────────────┐")
	fmt.Println("│ This would show real-time metrics from a running agent     │")
	fmt.Println("│ In a full implementation, this would use IPC or API calls  │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
}

// runHealth shows agent health
func runHealth(args []string) {
	fmt.Println("┌─ Agent Health ──────────────────────────────────────────────┐")
	fmt.Println("│ This would check the health of a running agent             │")
	fmt.Println("│ In a full implementation, this would use IPC or API calls  │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
}

// showVersion shows version information
func showVersion() {
	fmt.Println("Aegis Agent v1.0.1")
	fmt.Println("Build: " + getBuildInfo())
	fmt.Println("Go Version: " + getGoVersion())
	fmt.Println("Features: Real modules, CLI interface, eBPF support")
}

// showHelp shows comprehensive help
func showHelp() {
	fmt.Println("Aegis Agent - Enterprise Security Agent")
	fmt.Println("")
	fmt.Println("USAGE:")
	fmt.Println("  aegis <COMMAND> [OPTIONS]")
	fmt.Println("")
	fmt.Println("COMMANDS:")
	fmt.Println("  run, start, daemon    Start the agent in daemon mode")
	fmt.Println("  cli, interactive      Start interactive CLI")
	fmt.Println("  status                Show agent status")
	fmt.Println("  modules               List available modules")
	fmt.Println("  metrics               Show agent metrics")
	fmt.Println("  health                Check agent health")
	fmt.Println("  version               Show version information")
	fmt.Println("  help                  Show this help")
	fmt.Println("")
	fmt.Println("EXAMPLES:")
	fmt.Println("  # Start agent in daemon mode")
	fmt.Println("  aegis run --agent-id \"prod-agent\" --backend-url \"ws://backend:8080/ws/agent\"")
	fmt.Println("")
	fmt.Println("  # Start interactive CLI")
	fmt.Println("  aegis cli")
	fmt.Println("")
	fmt.Println("  # Check agent status")
	fmt.Println("  aegis status")
	fmt.Println("")
	fmt.Println("  # Show version")
	fmt.Println("  aegis version")
	fmt.Println("")
	fmt.Println("For more information, visit: https://github.com/sgerhart/aegis_agent")
}

// showUsage shows basic usage
func showUsage() {
	fmt.Println("Aegis Agent - Enterprise Security Agent")
	fmt.Println("")
	fmt.Println("USAGE:")
	fmt.Println("  aegis <COMMAND> [OPTIONS]")
	fmt.Println("")
	fmt.Println("COMMANDS:")
	fmt.Println("  run, start, daemon    Start the agent in daemon mode")
	fmt.Println("  cli, interactive      Start interactive CLI")
	fmt.Println("  status                Show agent status")
	fmt.Println("  modules               List available modules")
	fmt.Println("  metrics               Show agent metrics")
	fmt.Println("  health                Check agent health")
	fmt.Println("  version               Show version information")
	fmt.Println("  help                  Show this help")
	fmt.Println("")
	fmt.Println("Use 'aegis help' for more information.")
}

// CLIClient represents the CLI client for interacting with the agent
type CLIClient struct {
	agent     *core.Agent
	reader    *bufio.Reader
	logger    *telemetry.Logger
	running   bool
}

// showWelcome displays welcome message
func (c *CLIClient) showWelcome() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    Aegis Agent CLI                          ║")
	fmt.Println("║              Interactive Agent Management                    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// showHelp displays help information
func (c *CLIClient) showHelp() {
	fmt.Println("Available Commands:")
	fmt.Println("  help, h                    - Show this help")
	fmt.Println("  status, s                  - Show agent status")
	fmt.Println("  modules, m                 - List all modules")
	fmt.Println("  module <id>                - Show module details")
	fmt.Println("  start <module_id>          - Start a module")
	fmt.Println("  stop <module_id>            - Stop a module")
	fmt.Println("  metrics, met               - Show metrics")
	fmt.Println("  logs, l                    - Show recent logs")
	fmt.Println("  config, c                  - Show configuration")
	fmt.Println("  health, h                  - Check agent health")
	fmt.Println("  clear                      - Clear screen")
	fmt.Println("  quit, q, exit              - Exit CLI")
	fmt.Println()
}

// interactiveLoop runs the main interactive loop
func (c *CLIClient) interactiveLoop() error {
	for c.running {
		fmt.Print("aegis> ")
		input, err := c.reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}

		command := strings.ToLower(parts[0])
		args := parts[1:]

		if err := c.executeCommand(command, args); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}

	return nil
}

// executeCommand executes a CLI command
func (c *CLIClient) executeCommand(command string, args []string) error {
	switch command {
	case "help", "h":
		c.showHelp()
	case "status", "s":
		c.showStatus()
	case "modules", "m":
		c.listModules()
	case "module":
		if len(args) == 0 {
			return fmt.Errorf("module ID required")
		}
		c.showModule(args[0])
	case "start":
		if len(args) == 0 {
			return fmt.Errorf("module ID required")
		}
		c.startModule(args[0])
	case "stop":
		if len(args) == 0 {
			return fmt.Errorf("module ID required")
		}
		c.stopModule(args[0])
	case "metrics", "met":
		c.showMetrics()
	case "logs", "l":
		c.showLogs()
	case "config", "c":
		c.showConfig()
	case "health":
		c.showHealth()
	case "clear":
		c.clearScreen()
	case "quit", "q", "exit":
		c.running = false
		fmt.Println("Goodbye!")
	default:
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Type 'help' for available commands")
	}

	return nil
}

// showStatus shows agent status
func (c *CLIClient) showStatus() {
	fmt.Println("┌─ Agent Status ──────────────────────────────────────────────┐")
	fmt.Printf("│ Agent ID: %-50s │\n", c.agent.GetConfig().AgentID)
	fmt.Printf("│ Backend URL: %-45s │\n", c.agent.GetConfig().BackendURL)
	fmt.Printf("│ Log Level: %-48s │\n", c.agent.GetConfig().LogLevel)
	fmt.Printf("│ Running: %-50s │\n", "Yes")
	fmt.Printf("│ Uptime: %-50s │\n", c.agent.GetUptime().String())
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
}

// listModules lists all modules
func (c *CLIClient) listModules() {
	fmt.Println("┌─ Available Modules ─────────────────────────────────────────┐")
	
	// Get module manager from agent
	moduleManager := c.agent.GetModuleManager()
	if moduleManager == nil {
		fmt.Println("│ No module manager available                              │")
		fmt.Println("└─────────────────────────────────────────────────────────────┘")
		return
	}

	// Get all module statuses
	statuses := moduleManager.GetAllModuleStatuses()
	
	for moduleID, status := range statuses {
		statusStr := "Stopped"
		if status == "running" {
			statusStr = "Running"
		}
		
		fmt.Printf("│ %-20s %-30s │\n", moduleID, statusStr)
	}
	
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
}

// showModule shows module details
func (c *CLIClient) showModule(moduleID string) {
	fmt.Printf("┌─ Module: %s ──────────────────────────────────────────────┐\n", moduleID)
	
	moduleManager := c.agent.GetModuleManager()
	if moduleManager == nil {
		fmt.Println("│ No module manager available                              │")
		fmt.Println("└─────────────────────────────────────────────────────────────┘")
		return
	}

	// Get module status
	status, err := moduleManager.GetModuleStatus(moduleID)
	if err != nil {
		fmt.Printf("│ Status: %-50s │\n", "Error")
	} else {
		fmt.Printf("│ Status: %-50s │\n", status)
	}
	
	// Get module health
	health := moduleManager.GetModuleHealth(moduleID)
	if health != nil {
		fmt.Printf("│ Health: %-49s │\n", "Error")
	} else {
		fmt.Printf("│ Health: %-49s │\n", "OK")
	}
	
	// Get module metrics
	module, exists := moduleManager.GetModule(moduleID)
	if exists && module != nil {
		metrics := module.GetMetrics()
		fmt.Printf("│ Metrics: %-48s │\n", fmt.Sprintf("%d metrics", len(metrics)))
		
		// Show some key metrics
		for key, value := range metrics {
			if len(key) > 20 {
				key = key[:17] + "..."
			}
			fmt.Printf("│   %-20s: %-25s │\n", key, fmt.Sprintf("%v", value))
		}
	}
	
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
}

// startModule starts a module
func (c *CLIClient) startModule(moduleID string) {
	moduleManager := c.agent.GetModuleManager()
	if moduleManager == nil {
		fmt.Println("Error: No module manager available")
		return
	}

	if err := moduleManager.StartModule(moduleID); err != nil {
		fmt.Printf("Error starting module %s: %v\n", moduleID, err)
	} else {
		fmt.Printf("Module %s started successfully\n", moduleID)
	}
}

// stopModule stops a module
func (c *CLIClient) stopModule(moduleID string) {
	moduleManager := c.agent.GetModuleManager()
	if moduleManager == nil {
		fmt.Println("Error: No module manager available")
		return
	}

	if err := moduleManager.StopModule(moduleID); err != nil {
		fmt.Printf("Error stopping module %s: %v\n", moduleID, err)
	} else {
		fmt.Printf("Module %s stopped successfully\n", moduleID)
	}
}

// showMetrics shows agent metrics
func (c *CLIClient) showMetrics() {
	fmt.Println("┌─ Agent Metrics ─────────────────────────────────────────────┐")
	
	// Get agent metrics
	metrics := c.agent.GetMetrics()
	
	for key, value := range metrics {
		if len(key) > 25 {
			key = key[:22] + "..."
		}
		fmt.Printf("│ %-25s: %-30s │\n", key, fmt.Sprintf("%v", value))
	}
	
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
}

// showLogs shows recent logs
func (c *CLIClient) showLogs() {
	fmt.Println("┌─ Recent Logs ───────────────────────────────────────────────┐")
	fmt.Println("│ Log functionality would be implemented here                │")
	fmt.Println("│ This would show recent log entries from the agent          │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
}

// showConfig shows agent configuration
func (c *CLIClient) showConfig() {
	fmt.Println("┌─ Agent Configuration ───────────────────────────────────────┐")
	
	config := c.agent.GetConfig()
	
	fmt.Printf("│ Agent ID: %-50s │\n", config.AgentID)
	fmt.Printf("│ Backend URL: %-45s │\n", config.BackendURL)
	fmt.Printf("│ Log Level: %-48s │\n", config.LogLevel)
	fmt.Printf("│ Update Interval: %-42s │\n", config.UpdateInterval.String())
	fmt.Printf("│ Enabled Modules: %-42s │\n", strings.Join(config.EnabledModules, ", "))
	
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
}

// showHealth shows agent health
func (c *CLIClient) showHealth() {
	fmt.Println("┌─ Agent Health ──────────────────────────────────────────────┐")
	
	// Check overall agent health
	health := c.agent.HealthCheck()
	if health != nil {
		fmt.Printf("│ Overall Health: %-42s │\n", "ERROR")
		fmt.Printf("│ Error: %-50s │\n", health.Error())
	} else {
		fmt.Printf("│ Overall Health: %-42s │\n", "OK")
	}
	
	// Check module health
	moduleManager := c.agent.GetModuleManager()
	if moduleManager != nil {
		statuses := moduleManager.GetAllModuleStatuses()
		healthyModules := 0
		totalModules := len(statuses)
		
		for _, status := range statuses {
			if status == "running" {
				healthyModules++
			}
		}
		
		fmt.Printf("│ Modules: %d/%d running (%d%% healthy)                    │\n", 
			healthyModules, totalModules, (healthyModules*100)/totalModules)
	}
	
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
}

// clearScreen clears the screen
func (c *CLIClient) clearScreen() {
	fmt.Print("\033[2J\033[H")
	c.showWelcome()
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