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
	"runtime"
	"syscall"
	"time"

	"agents/aegis/internal/ebpf"
	"agents/aegis/internal/network"
	"agents/aegis/internal/telemetry"
	"agents/aegis/pkg/models"
)

func main() {
	// Define flags
	var (
		observeMode    = flag.Bool("observe", false, "Enable observe mode (log only, no blocking)")
		blockMode      = flag.Bool("block", false, "Enable block mode (actually block traffic)")
		dryRun         = flag.Bool("dry-run", false, "Enable dry-run mode (no actual policy application)")
		iface          = flag.String("iface", "", "Network interface to attach to (default: all)")
		noTC           = flag.Bool("no-tc", false, "Skip TC program attachment")
		noCG           = flag.Bool("no-cg", false, "Skip cgroup program attachment")
		visibility     = flag.Bool("visibility", true, "Enable host visibility collection")
		telemetryURL   = flag.String("telemetry-url", getenv("NATS_URL", "nats://localhost:4222"), "NATS URL for telemetry")
		hostID         = flag.String("host-id", getenv("AGENT_HOST_ID", "host-unknown"), "Host ID")
		policyFile     = flag.String("policy", "", "Policy file to apply")
		verbose        = flag.Bool("verbose", false, "Enable verbose logging")
	)
	flag.Parse()

	// Set up logging
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	log.Printf("[main] Starting Aegis Agent Cap7.10 (HostID: %s)", *hostID)

	// Determine enforcement mode
	var enforceMode string
	if *blockMode {
		enforceMode = "block"
	} else if *observeMode {
		enforceMode = "observe"
	} else {
		// Default to observe mode for safety
		enforceMode = "observe"
		log.Printf("[main] No mode specified, defaulting to observe mode")
	}

	log.Printf("[main] Enforcement mode: %s", enforceMode)
	log.Printf("[main] Dry-run: %t", *dryRun)

	// Initialize telemetry
	eventEmitter := telemetry.NewConsoleEmitter(*hostID)
	if *telemetryURL != "" {
		log.Printf("[main] Telemetry URL: %s", *telemetryURL)
	}

	// Initialize eBPF maps
	var mapManager ebpf.MapManagerInterface
	if runtime.GOOS == "linux" {
		realMapManager, err := ebpf.NewSimpleMapManager()
		if err != nil {
			log.Printf("[main] Failed to initialize real eBPF maps, using mock: %v", err)
			mapManager = ebpf.NewMockMapManager()
		} else {
			mapManager = realMapManager
		}
	} else {
		log.Printf("[main] Non-Linux system, using mock eBPF maps")
		mapManager = ebpf.NewMockMapManager()
	}
	defer mapManager.Close()

	// Initialize policy writer
	policyWriter := ebpf.NewPolicyWriter(mapManager, eventEmitter)

	// Initialize interface management
	backendURL := getenv("ACTIONS_API_URL", "http://localhost:8083")
	interfaceManager := network.NewInterfaceManager(backendURL)
	defer interfaceManager.Close()

	// Auto-detect default interface for backend connectivity
	defaultIface, err := interfaceManager.GetDefaultInterface()
	if err != nil {
		log.Printf("[main] Warning: Failed to detect default interface: %v", err)
		log.Printf("[main] Available interfaces:")
		if interfaces, err := interfaceManager.GetEnforcementInterfaces(); err == nil {
			for _, iface := range interfaces {
				log.Printf("[main]   - %s (up: %v, addresses: %v)", iface.Name, iface.IsUp, iface.Addresses)
			}
		}
	} else {
		log.Printf("[main] Default interface for backend connectivity: %s (index %d)", defaultIface.Name, defaultIface.Index)
		log.Printf("[main] Interface addresses: %v", defaultIface.Addresses)
	}

	// Attach programs based on configuration
	if !*noTC {
		if *iface != "" {
			// Use specified interface
			if err := interfaceManager.AttachToInterface(*iface); err != nil {
				log.Fatalf("[main] Failed to attach to interface %s: %v", *iface, err)
			}
		} else if defaultIface != nil {
			// Use default interface for backend connectivity
			if err := interfaceManager.AttachToDefaultInterface(); err != nil {
				log.Fatalf("[main] Failed to attach to default interface: %v", err)
			}
		} else {
			// Fallback to all available interfaces
			if interfaces, err := interfaceManager.GetEnforcementInterfaces(); err == nil {
				var ifaceNames []string
				for _, iface := range interfaces {
					ifaceNames = append(ifaceNames, iface.Name)
				}
				if err := interfaceManager.AttachToInterfaces(ifaceNames); err != nil {
					log.Printf("[main] Warning: Failed to attach to some interfaces: %v", err)
				}
			}
		}
	}

	// Log attached interfaces
	attached := interfaceManager.GetAttachedInterfaces()
	log.Printf("[main] Attached to %d interfaces:", len(attached))
	for name, info := range attached {
		log.Printf("[main]   - %s (backend: %v, addresses: %v)", name, info.IsBackend, info.Addresses)
	}

	// Apply policy if specified
	if *policyFile != "" {
		if err := applyPolicyFromFile(policyWriter, *policyFile, enforceMode); err != nil {
			log.Fatalf("[main] Failed to apply policy: %v", err)
		}
	} else {
		// Apply default policy (block 8.8.8.8)
		if err := applyDefaultPolicy(policyWriter, enforceMode); err != nil {
			log.Fatalf("[main] Failed to apply default policy: %v", err)
		}
	}

	// Initialize HTTP server for status and backend interface API
	httpAddr := getenv("AGENT_HTTP_ADDR", ":7070")
	mux := http.NewServeMux()
	
	// Health check endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	
	// Status endpoint
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		statusData := map[string]any{
			"host_id":         *hostID,
			"enforce_mode":    enforceMode,
			"dry_run":         *dryRun,
			"attached_ifaces": len(attached),
			"uptime_seconds":  time.Since(startTime).Seconds(),
		}
		json.NewEncoder(w).Encode(statusData)
	})

	// Backend interface API
	agentUID := getenv("AGENT_UID", "agent-unknown")
	backendAPI := network.NewBackendInterfaceAPI(interfaceManager, agentUID, *hostID)
	backendAPI.RegisterRoutes(mux)

	// Start HTTP server
	go func() {
		log.Printf("[main] HTTP server listening on %s", httpAddr)
		if err := http.ListenAndServe(httpAddr, mux); err != nil && err != http.ErrServerClosed {
			log.Printf("[main] HTTP server error: %v", err)
		}
	}()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start visibility reporting
	visibilityTicker := time.NewTicker(60 * time.Second)
	defer visibilityTicker.Stop()

	// Main loop
	log.Printf("[main] Agent running. Press Ctrl+C to stop.")
	for {
		select {
		case <-sigChan:
			log.Printf("[main] Received shutdown signal")
			goto shutdown
		case <-visibilityTicker.C:
			if *visibility {
				reportVisibility(eventEmitter, *hostID)
			}
		}
	}

shutdown:
	// Cleanup
	log.Printf("[main] Shutting down...")
	log.Printf("[main] Shutdown complete")
}

// applyPolicyFromFile applies a policy from a file
func applyPolicyFromFile(policyWriter *ebpf.PolicyWriter, policyFile string, enforceMode string) error {
	log.Printf("[main] Applying policy from file: %s", policyFile)

	// Read policy file
	content, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	// Create assignment from file content
	assignment := &models.Assignment{
		ID:        "file-policy",
		PolicyID:  "file-policy",
		Version:   "1",
		CreatedAt: time.Now(),
		DryRun:    false,
		Bundle: models.Bundle{
			ID:        "file-bundle",
			Content:   content,
			Hash:      "file-hash",
			Algo:      "Ed25519",
			KeyID:     "file-key",
			CreatedAt: time.Now(),
		},
	}

	// Create snapshot
	snapshot, err := ebpf.CreateSnapshotFromAssignment(assignment)
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	// Set mode
	snapshot.Mode = enforceMode

	// Apply snapshot
	ctx := context.Background()
	return policyWriter.ApplySnapshot(ctx, snapshot)
}

// applyDefaultPolicy applies a default policy (block 8.8.8.8)
func applyDefaultPolicy(policyWriter *ebpf.PolicyWriter, enforceMode string) error {
	log.Printf("[main] Applying default policy (block 8.8.8.8)")

	// Create default assignment
	assignment := &models.Assignment{
		ID:        "default-policy",
		PolicyID:  "block-google-dns",
		Version:   "1",
		CreatedAt: time.Now(),
		DryRun:    false,
		Bundle: models.Bundle{
			ID:        "default-bundle",
			Content:   []byte("block 8.8.8.8"),
			Hash:      "default-hash",
			Algo:      "Ed25519",
			KeyID:     "default-key",
			CreatedAt: time.Now(),
		},
	}

	// Create snapshot
	snapshot, err := ebpf.CreateSnapshotFromAssignment(assignment)
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	// Set mode
	snapshot.Mode = enforceMode

	// Apply snapshot
	ctx := context.Background()
	return policyWriter.ApplySnapshot(ctx, snapshot)
}

// reportVisibility reports host visibility
func reportVisibility(eventEmitter *telemetry.ConsoleEmitter, hostID string) {
	// Create visibility frame
	visibilityFrame := map[string]interface{}{
		"host_id": hostID,
		"ts":      time.Now().UTC(),
		"procs":   []map[string]interface{}{},
		"flows":   []map[string]interface{}{},
	}

	// Emit visibility event
	eventEmitter.Emit(telemetry.Event{
		Type: telemetry.EventTypeVisibility,
		Data: visibilityFrame,
		Message: "Visibility frame: 0 processes, 0 flows",
	})

	log.Printf("[visibility] Reported visibility frame")
}

// getenv gets an environment variable with a default value
func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
