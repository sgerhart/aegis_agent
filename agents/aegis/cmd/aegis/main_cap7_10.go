package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agents/aegis/internal/ebpf"
	"agents/aegis/internal/enforce"
	"agents/aegis/internal/telemetry"
	"agents/aegis/internal/visibility"
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
	var enforceMode enforce.Mode
	if *blockMode {
		enforceMode = enforce.ModeBlock
	} else if *observeMode {
		enforceMode = enforce.ModeObserve
	} else {
		// Default to observe mode for safety
		enforceMode = enforce.ModeObserve
		log.Printf("[main] No mode specified, defaulting to observe mode")
	}

	log.Printf("[main] Enforcement mode: %s", enforceMode.String())
	log.Printf("[main] Dry-run: %t", *dryRun)

	// Initialize telemetry
	eventEmitter := telemetry.NewConsoleEmitter(*hostID)
	if *telemetryURL != "" {
		// TODO: Initialize NATS emitter
		log.Printf("[main] Telemetry URL: %s", *telemetryURL)
	}

	// Initialize eBPF maps
	mapManager, err := ebpf.NewMapManager()
	if err != nil {
		log.Fatalf("[main] Failed to initialize eBPF maps: %v", err)
	}
	defer mapManager.Close()

	// Initialize mode manager
	modeManager := enforce.NewModeManager(mapManager)
	if err := modeManager.SetMode(enforceMode); err != nil {
		log.Fatalf("[main] Failed to set enforcement mode: %v", err)
	}

	// Initialize decision manager
	decisionManager := enforce.NewDecisionManager(eventEmitter, modeManager)

	// Initialize policy writer
	policyWriter := ebpf.NewPolicyWriter(mapManager, eventEmitter)

	// Initialize program attachment
	attachManager := ebpf.NewAttachManager()
	if err := attachManager.LoadPrograms(); err != nil {
		log.Fatalf("[main] Failed to load eBPF programs: %v", err)
	}
	defer attachManager.Close()

	// Attach programs
	if !*noTC {
		if *iface != "" {
			if err := attachManager.AttachToInterface(*iface); err != nil {
				log.Fatalf("[main] Failed to attach to interface %s: %v", *iface, err)
			}
		} else {
			if err := attachManager.AttachToAllInterfaces(); err != nil {
				log.Fatalf("[main] Failed to attach to interfaces: %v", err)
			}
		}
	}

	if !*noCG {
		if err := attachManager.AttachToCgroup("/sys/fs/cgroup"); err != nil {
			log.Printf("[main] Warning: Failed to attach to cgroup: %v", err)
		}
	}

	// Initialize visibility collection
	var procSnapshotter *visibility.ProcSnapshotter
	var flowCollector *visibility.FlowCollector
	var execEventConsumer *visibility.ExecEventConsumer

	if *visibility {
		// Process snapshotter
		procSnapshotter = visibility.NewProcSnapshotter(30 * time.Second)
		if err := procSnapshotter.Start(); err != nil {
			log.Printf("[main] Warning: Failed to start proc snapshotter: %v", err)
		}

		// Flow collector
		flowCollector = visibility.NewFlowCollector(10 * time.Second)
		if err := flowCollector.Start(); err != nil {
			log.Printf("[main] Warning: Failed to start flow collector: %v", err)
		}

		// Exec event consumer (mock for now)
		execEventConsumer = visibility.MockExecEventConsumer()
		execEventConsumer.GenerateMockEvents()
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
				reportVisibility(eventEmitter, *hostID, procSnapshotter, flowCollector, execEventConsumer)
			}
		}
	}

shutdown:
	// Cleanup
	log.Printf("[main] Shutting down...")

	if procSnapshotter != nil {
		procSnapshotter.Stop()
	}

	if flowCollector != nil {
		flowCollector.Stop()
	}

	if execEventConsumer != nil {
		execEventConsumer.Close()
	}

	log.Printf("[main] Shutdown complete")
}

// applyPolicyFromFile applies a policy from a file
func applyPolicyFromFile(policyWriter *ebpf.PolicyWriter, policyFile string, enforceMode enforce.Mode) error {
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
		Version:   1,
		CreatedAt: time.Now(),
		DryRun:    false,
		Bundle: models.Bundle{
			ID:        "file-bundle",
			Content:   string(content),
			Hash:      "file-hash",
			Signature: "file-signature",
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
	snapshot.Mode = enforceMode.String()

	// Apply snapshot
	ctx := context.Background()
	return policyWriter.ApplySnapshot(ctx, snapshot)
}

// applyDefaultPolicy applies a default policy (block 8.8.8.8)
func applyDefaultPolicy(policyWriter *ebpf.PolicyWriter, enforceMode enforce.Mode) error {
	log.Printf("[main] Applying default policy (block 8.8.8.8)")

	// Create default assignment
	assignment := &models.Assignment{
		ID:        "default-policy",
		PolicyID:  "block-google-dns",
		Version:   1,
		CreatedAt: time.Now(),
		DryRun:    false,
		Bundle: models.Bundle{
			ID:        "default-bundle",
			Content:   "block 8.8.8.8",
			Hash:      "default-hash",
			Signature: "default-signature",
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
	snapshot.Mode = enforceMode.String()

	// Apply snapshot
	ctx := context.Background()
	return policyWriter.ApplySnapshot(ctx, snapshot)
}

// reportVisibility reports host visibility
func reportVisibility(eventEmitter *telemetry.EventEmitter, hostID string, procSnapshotter *visibility.ProcSnapshotter, flowCollector *visibility.FlowCollector, execEventConsumer *visibility.ExecEventConsumer) {
	// Get process information
	processes := procSnapshotter.GetLastSnapshot()
	procs := make([]map[string]interface{}, 0, len(processes))
	for _, proc := range processes {
		procs = append(procs, map[string]interface{}{
			"pid":        proc.PID,
			"ppid":       proc.PPID,
			"exe":        proc.Exe,
			"uid":        proc.UID,
			"args":       proc.Args,
			"start_time": proc.StartTime,
			"state":      proc.State,
			"threads":    proc.Threads,
		})
	}

	// Get flow information
	flows := flowCollector.GetFlows()
	flowList := make([]map[string]interface{}, 0, len(flows))
	for _, flow := range flows {
		flowList = append(flowList, map[string]interface{}{
			"pid":       flow.PID,
			"laddr":     flow.LAddr,
			"raddr":     flow.RAddr,
			"proto":     flow.Protocol,
			"dir":       flow.Direction,
			"pkts":      flow.Packets,
			"bytes":     flow.Bytes,
			"last_seen": flow.LastSeen,
			"state":     flow.State,
		})
	}

	// Create visibility frame
	visibilityFrame := map[string]interface{}{
		"host_id": hostID,
		"ts":      time.Now().UTC(),
		"procs":   procs,
		"flows":   flowList,
	}

	// Emit visibility event
	eventEmitter.Emit(telemetry.Event{
		Type: telemetry.EventVisibility,
		Data: visibilityFrame,
		Message: fmt.Sprintf("Visibility frame: %d processes, %d flows", len(procs), len(flowList)),
	})

	log.Printf("[visibility] Reported %d processes, %d flows", len(procs), len(flowList))
}

// getenv gets an environment variable with a default value
func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
