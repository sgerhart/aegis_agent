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

	"agents/aegis/internal/crypto"
	"agents/aegis/internal/ebpf"
	"agents/aegis/internal/enforce"
	"agents/aegis/internal/identity"
	"agents/aegis/internal/network"
	"agents/aegis/internal/rollout"
	"agents/aegis/internal/telemetry"
	"agents/aegis/internal/visibility"
	"agents/aegis/pkg/models"
)

var startTime = time.Now()

func main() {
	// Define flags - combining all capabilities
	var (
		// Cap 7.10 Enforcement flags
		observeMode    = flag.Bool("observe", false, "Enable observe mode (log only, no blocking)")
		blockMode      = flag.Bool("block", false, "Enable block mode (actually block traffic)")
		dryRun         = flag.Bool("dry-run", false, "Enable dry-run mode (no actual policy application)")
		iface          = flag.String("iface", "", "Network interface to attach to (default: auto-detect)")
		noTC           = flag.Bool("no-tc", false, "Skip TC program attachment")
		noCG           = flag.Bool("no-cg", false, "Skip cgroup program attachment")
		visibility     = flag.Bool("visibility", true, "Enable host visibility collection")
		
		// Cap 7.9 Safety flags
		mtls           = flag.Bool("mtls", false, "Enable mTLS for registry communication")
		trustStore     = flag.String("truststore", "/etc/aegis/truststore.json", "Path to trust store file")
		
		// Backend integration flags
		telemetryURL   = flag.String("telemetry-url", getenv("NATS_URL", "nats://localhost:4222"), "NATS URL for telemetry")
		actionsURL     = flag.String("actions-url", getenv("ACTIONS_API_URL", "http://localhost:8083"), "Actions API URL")
		registryURL    = flag.String("registry-url", getenv("AGENT_REGISTRY_URL", "http://localhost:8090"), "Registry URL")
		
		// General flags
		hostID         = flag.String("host-id", getenv("AGENT_HOST_ID", ""), "Host ID")
		agentID        = flag.String("agent-id", getenv("AGENT_ID", ""), "Agent ID")
		orgID          = flag.String("org-id", getenv("ORG_ID", "default"), "Organization ID")
		policyFile     = flag.String("policy", "", "Policy file to apply")
		httpAddr       = flag.String("http-addr", getenv("AGENT_HTTP_ADDR", ":7070"), "HTTP server address")
		verbose        = flag.Bool("verbose", false, "Enable verbose logging")
		register       = flag.Bool("register", true, "Register with backend on startup")
	)
	flag.Parse()

	// Check environment variable overrides
	if os.Getenv("AEGIS_DRY_RUN") == "true" {
		*dryRun = true
	}
	if os.Getenv("AEGIS_MTLS") == "true" {
		*mtls = true
	}
	if trustStoreEnv := os.Getenv("AEGIS_TRUSTSTORE"); trustStoreEnv != "" {
		*trustStore = trustStoreEnv
	}
	if verboseEnv := os.Getenv("AEGIS_VERBOSE"); verboseEnv == "true" {
		*verbose = true
	}

	// Set up logging
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	log.Printf("[main] Starting Aegis Agent Ubuntu Complete")
	log.Printf("[main] Version: Cap 7.9 Safety + Cap 7.10 Enforcement + Backend Integration")

	// Resolve identity
	if *hostID == "" {
		*hostID = identity.ResolveHostID()
	}
	if *agentID == "" {
		*agentID = generateAgentID(*hostID)
	}

	log.Printf("[main] Host ID: %s, Agent ID: %s, Org ID: %s", *hostID, *agentID, *orgID)

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
	log.Printf("[main] Dry-run: %t, mTLS: %t", *dryRun, *mtls)

	// Initialize cryptographic components (Cap 7.9)
	var trustMgr *crypto.TrustStoreManager
	var err error
	if *mtls {
		trustMgr, err = crypto.NewTrustStoreManager(*trustStore)
		if err != nil {
			log.Printf("[main] Warning: Failed to initialize trust store: %v", err)
			log.Printf("[main] Continuing without cryptographic verification")
		} else {
			log.Printf("[main] Trust store initialized: %s", *trustStore)
		}
	}

	// Initialize backend registration
	var agentUID, bootstrapToken string
	if *register {
		pub, priv, err := identity.LoadOrCreateKeypair()
		if err != nil {
			log.Printf("[main] Warning: Failed to load/create identity keypair: %v", err)
		} else {
			log.Printf("[main] Loaded identity keypair, public key: %s", identity.PubKeyB64(pub))
			
			// Register with actions API
			agentUID, bootstrapToken, err = identity.Register(*actionsURL, *orgID, *hostID, pub, priv)
			if err != nil {
				log.Printf("[main] Warning: Registration failed: %v", err)
				log.Printf("[main] Continuing without registration...")
			} else {
				log.Printf("[main] Registered successfully: agent_uid=%s", agentUID)
			}
		}
	}

	// Initialize telemetry (Cap 7.9 + 7.10)
	eventEmitter := telemetry.NewConsoleEmitter(*hostID)
	if *telemetryURL != "" {
		// TODO: Initialize NATS emitter when ready
		log.Printf("[main] Telemetry URL configured: %s", *telemetryURL)
	}

	// Initialize eBPF maps and enforcement (Cap 7.10)
	var mapManager ebpf.MapManagerInterface
	if runtime.GOOS == "linux" {
		realMapManager, err := ebpf.NewSimpleMapManager()
		if err != nil {
			log.Printf("[main] Failed to initialize real eBPF maps, using mock: %v", err)
			mapManager = ebpf.NewMockMapManager()
		} else {
			mapManager = realMapManager
			log.Printf("[main] Real eBPF maps initialized")
		}
	} else {
		log.Printf("[main] Non-Linux system, using mock eBPF maps")
		mapManager = ebpf.NewMockMapManager()
	}
	defer mapManager.Close()

	// Initialize policy writer with safety features
	policyWriter := ebpf.NewPolicyWriter(mapManager, eventEmitter)

	// Initialize network interface management (Cap 7.10)
	interfaceManager := network.NewInterfaceManager(*actionsURL)
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

	// Attach eBPF programs based on configuration
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

	// Initialize visibility collection (Cap 7.10)
	var procSnapshotter *visibility.ProcSnapshotter
	var flowCollector *visibility.FlowCollector
	var execEventConsumer *visibility.ExecEventConsumer

	if *visibility {
		// Process snapshotter
		procSnapshotter = visibility.NewProcSnapshotter(30 * time.Second)
		if err := procSnapshotter.Start(); err != nil {
			log.Printf("[main] Warning: Failed to start proc snapshotter: %v", err)
		} else {
			log.Printf("[main] Process snapshotter started")
		}

		// Flow collector
		flowCollector = visibility.NewFlowCollector(10 * time.Second)
		if err := flowCollector.Start(); err != nil {
			log.Printf("[main] Warning: Failed to start flow collector: %v", err)
		} else {
			log.Printf("[main] Flow collector started")
		}

		// Exec event consumer (for now, using mock)
		execEventConsumer = visibility.MockExecEventConsumer()
		execEventConsumer.GenerateMockEvents()
		log.Printf("[main] Exec event consumer started (mock)")
	}

	// Apply policy if specified
	if *policyFile != "" {
		if err := applyPolicyFromFile(policyWriter, *policyFile, enforceMode, trustMgr, *dryRun); err != nil {
			log.Fatalf("[main] Failed to apply policy: %v", err)
		}
	} else {
		// Apply default policy (block 8.8.8.8)
		if err := applyDefaultPolicy(policyWriter, enforceMode, *dryRun); err != nil {
			log.Fatalf("[main] Failed to apply default policy: %v", err)
		}
	}

	// Initialize HTTP server for status and backend interface API
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
			"agent_id":        *agentID,
			"agent_uid":       agentUID,
			"org_id":          *orgID,
			"enforce_mode":    enforceMode,
			"dry_run":         *dryRun,
			"mtls_enabled":    *mtls,
			"registered":      agentUID != "",
			"attached_ifaces": len(attached),
			"visibility":      *visibility,
			"uptime_seconds":  time.Since(startTime).Seconds(),
			"version":         "Cap7.9+7.10 Complete",
			"actions_url":     *actionsURL,
			"registry_url":    *registryURL,
			"telemetry_url":   *telemetryURL,
		}
		json.NewEncoder(w).Encode(statusData)
	})

	// Backend interface API
	backendAPI := network.NewBackendInterfaceAPI(interfaceManager, agentUID, *hostID)
	backendAPI.RegisterRoutes(mux)

	// Start HTTP server
	srv := &http.Server{Addr: *httpAddr, Handler: mux}
	go func() {
		log.Printf("[main] HTTP server listening on %s", *httpAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[main] HTTP server error: %v", err)
		}
	}()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start visibility reporting
	visibilityTicker := time.NewTicker(60 * time.Second)
	defer visibilityTicker.Stop()

	// Start heartbeat
	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	// Emit startup event
	eventEmitter.Emit(telemetry.Event{
		Type: telemetry.EventTypeCounter,
		Data: map[string]interface{}{
			"metric": "agent_started",
			"value":  1,
			"labels": map[string]string{
				"host_id":      *hostID,
				"agent_id":     *agentID,
				"agent_uid":    agentUID,
				"version":      "Cap7.9+7.10",
				"enforce_mode": enforceMode,
				"dry_run":      fmt.Sprintf("%v", *dryRun),
			},
		},
		Message: fmt.Sprintf("Aegis Agent started: %s", *hostID),
	})

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
		case <-heartbeatTicker.C:
			log.Printf("[main] Heartbeat - host_id=%s agent_uid=%s uptime=%.0fs", 
				*hostID, agentUID, time.Since(startTime).Seconds())
		}
	}

shutdown:
	// Cleanup
	log.Printf("[main] Shutting down...")

	// Stop HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[main] HTTP server shutdown error: %v", err)
	}

	// Stop visibility collectors
	if procSnapshotter != nil {
		procSnapshotter.Stop()
	}
	if flowCollector != nil {
		flowCollector.Stop()
	}
	if execEventConsumer != nil {
		execEventConsumer.Close()
	}

	// Emit shutdown event
	eventEmitter.Emit(telemetry.Event{
		Type: telemetry.EventTypeCounter,
		Data: map[string]interface{}{
			"metric": "agent_stopped",
			"value":  1,
			"labels": map[string]string{
				"host_id":   *hostID,
				"agent_id":  *agentID,
				"agent_uid": agentUID,
			},
		},
		Message: fmt.Sprintf("Aegis Agent stopped: %s", *hostID),
	})

	log.Printf("[main] Shutdown complete")
}

// applyPolicyFromFile applies a policy from a file with safety features
func applyPolicyFromFile(policyWriter *ebpf.PolicyWriter, policyFile string, enforceMode string, trustMgr *crypto.TrustStoreManager, dryRun bool) error {
	log.Printf("[main] Applying policy from file: %s (dry-run: %v)", policyFile, dryRun)

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
		DryRun:    dryRun,
		Bundle: models.Bundle{
			ID:        "file-bundle",
			Content:   content,
			Hash:      "file-hash",
			Algo:      "Ed25519",
			KeyID:     "file-key",
			CreatedAt: time.Now(),
		},
	}

	// Verify bundle if trust manager is available
	if trustMgr != nil {
		verifier := trustMgr.GetVerifier()
		if err := verifier.VerifyBundle(&assignment.Bundle); err != nil {
			return fmt.Errorf("policy verification failed: %w", err)
		}
		log.Printf("[main] Policy verification successful")
	} else {
		log.Printf("[main] Warning: Policy applied without cryptographic verification")
	}

	// Create snapshot for rollback
	if !dryRun {
		if err := rollout.CreateSnapshot("pre-policy-apply"); err != nil {
			log.Printf("[main] Warning: Failed to create rollback snapshot: %v", err)
		}
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
	if err := policyWriter.ApplySnapshot(ctx, snapshot); err != nil {
		// Rollback on failure
		if !dryRun {
			if rollbackErr := rollout.RollbackToSnapshot("pre-policy-apply"); rollbackErr != nil {
				log.Printf("[main] Rollback failed: %v", rollbackErr)
			} else {
				log.Printf("[main] Rolled back due to apply failure")
			}
		}
		return fmt.Errorf("failed to apply policy: %w", err)
	}

	log.Printf("[main] Policy applied successfully")
	return nil
}

// applyDefaultPolicy applies a default policy (block 8.8.8.8)
func applyDefaultPolicy(policyWriter *ebpf.PolicyWriter, enforceMode string, dryRun bool) error {
	log.Printf("[main] Applying default policy (block 8.8.8.8) in %s mode (dry-run: %v)", enforceMode, dryRun)

	// Create default assignment
	assignment := &models.Assignment{
		ID:        "default-policy",
		PolicyID:  "block-google-dns",
		Version:   "1",
		CreatedAt: time.Now(),
		DryRun:    dryRun,
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
func reportVisibility(eventEmitter *telemetry.ConsoleEmitter, hostID string, procSnapshotter *visibility.ProcSnapshotter, flowCollector *visibility.FlowCollector, execEventConsumer *visibility.ExecEventConsumer) {
	var procs []map[string]interface{}
	var flows []map[string]interface{}

	// Get process information
	if procSnapshotter != nil {
		processes := procSnapshotter.GetLastSnapshot()
		procs = make([]map[string]interface{}, 0, len(processes))
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
	}

	// Get flow information
	if flowCollector != nil {
		flowData := flowCollector.GetFlows()
		flows = make([]map[string]interface{}, 0, len(flowData))
		for _, flow := range flowData {
			flows = append(flows, map[string]interface{}{
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
	}

	// Create visibility frame
	visibilityFrame := map[string]interface{}{
		"host_id": hostID,
		"ts":      time.Now().UTC(),
		"procs":   procs,
		"flows":   flows,
	}

	// Emit visibility event
	eventEmitter.Emit(telemetry.Event{
		Type: telemetry.EventTypeVisibility,
		Data: visibilityFrame,
		Message: fmt.Sprintf("Visibility frame: %d processes, %d flows", len(procs), len(flows)),
	})

	log.Printf("[visibility] Reported %d processes, %d flows", len(procs), len(flows))
}

// generateAgentID generates an agent ID
func generateAgentID(hostID string) string {
	// Try environment variable first
	if agentID := os.Getenv("AGENT_ID"); agentID != "" {
		return agentID
	}
	
	// Generate based on host ID and timestamp
	return fmt.Sprintf("agent-%s-%d", hostID, time.Now().Unix())
}

// getenv gets an environment variable with a default value
func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
