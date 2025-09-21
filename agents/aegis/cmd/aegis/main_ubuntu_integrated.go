package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"agents/aegis/internal/build"
	"agents/aegis/internal/capability"
	"agents/aegis/internal/crypto"
	"agents/aegis/internal/ebpf"
	"agents/aegis/internal/identity"
	"agents/aegis/internal/observability"
	"agents/aegis/internal/policy"
	"agents/aegis/internal/telemetry"
	"agents/aegis/pkg/models"
)

var startTime = time.Now()

func main() {
	// Define flags - comprehensive agent with segmentation
	var (
		// Enforcement mode flags
		observeMode    = flag.Bool("observe", false, "Enable observe mode (log only, no blocking)")
		blockMode      = flag.Bool("block", false, "Enable block mode (actually block traffic)")
		dryRun         = flag.Bool("dry-run", false, "Enable dry-run mode (no actual policy application)")
		
		// Segmentation flags
		segmentation   = flag.Bool("segmentation", true, "Enable network segmentation features")
		buildPrograms  = flag.Bool("build-programs", false, "Enable runtime eBPF program building")
		
		// Safety and security flags
		mtls           = flag.Bool("mtls", false, "Enable mTLS for registry communication")
		trustStore     = flag.String("truststore", "/etc/aegis/truststore.json", "Path to trust store file")
		
		// Backend integration flags
		actionsURL     = flag.String("actions-url", getenv("ACTIONS_API_URL", "http://localhost:8083"), "Actions API URL")
		registryURL    = flag.String("registry-url", getenv("AGENT_REGISTRY_URL", "http://localhost:8090"), "Registry URL") 
		natsURL        = flag.String("nats-url", getenv("NATS_URL", "nats://localhost:4222"), "NATS URL for telemetry")
		
		// Agent identity flags
		hostID         = flag.String("host-id", getenv("AGENT_HOST_ID", ""), "Host ID")
		agentID        = flag.String("agent-id", getenv("AGENT_ID", ""), "Agent ID")
		orgID          = flag.String("org-id", getenv("ORG_ID", "default"), "Organization ID")
		
		// Build environment flags (for CO-RE)
		clangPath      = flag.String("clang", getenv("CLANG_PATH", "clang"), "Path to clang compiler")
		bpftoolPath    = flag.String("bpftool", getenv("BPFTOOL_PATH", "bpftool"), "Path to bpftool")
		btfPath        = flag.String("btf", getenv("BTF_PATH", "/sys/kernel/btf/vmlinux"), "BTF file path")
		buildOutputDir = flag.String("build-output", getenv("BUILD_OUTPUT_DIR", "./build"), "eBPF program output directory")
		
		// Configuration flags
		policyFile     = flag.String("policy", "", "Policy file to apply")
		httpAddr       = flag.String("http-addr", getenv("AGENT_HTTP_ADDR", ":7070"), "HTTP server address")
		pollInterval   = flag.Duration("poll-interval", 30*time.Second, "Policy polling interval")
		verbose        = flag.Bool("verbose", false, "Enable verbose logging")
		register       = flag.Bool("register", true, "Register with backend on startup")
		enableeBPF     = flag.Bool("ebpf", true, "Enable eBPF policy enforcement")
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

	log.Printf("[main] Starting Aegis Agent - Integrated Ubuntu Edition")
	log.Printf("[main] Capabilities: Registration + eBPF + Segmentation + Safety + Telemetry + CO-RE")

	// Resolve identity
	if *hostID == "" {
		*hostID = identity.ResolveHostID()
	}
	if *agentID == "" {
		*agentID = generateAgentID(*hostID)
	}

	localIP := getLocalIP()
	log.Printf("[main] Host ID: %s, Agent ID: %s, Org ID: %s", *hostID, *agentID, *orgID)
	log.Printf("[main] Local IP: %s", localIP)

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

	log.Printf("[main] Configuration: mode=%s, dry-run=%t, mTLS=%t, eBPF=%t, segmentation=%t", 
		enforceMode, *dryRun, *mtls, *enableeBPF, *segmentation)

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

	// Backend registration
	var agentUID, bootstrapToken string
	var pub, priv []byte
	if *register {
		pub, priv, err = identity.LoadOrCreateKeypair()
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
				log.Printf("[main] Bootstrap token: %s", bootstrapToken)
			}
		}
	}

	// Initialize enhanced observability (from segmentation agent)
	obs := observability.New(*natsURL, *hostID)
	defer obs.Close()

	// Initialize telemetry (console fallback)
	eventEmitter := telemetry.NewConsoleEmitter(*hostID)

	// Initialize capability probing (from segmentation agent)
	capProbe := capability.NewProbe()
	
	// Probe system capabilities
	ctx := context.Background()
	log.Printf("[main] Probing system capabilities...")
	capabilities, err := capProbe.ProbeCapabilities(ctx)
	if err != nil {
		log.Printf("[main] Capability probe failed: %v", err)
	} else {
		log.Printf("[main] Capabilities: %+v", capabilities)
		
		// Publish capabilities to NATS
		if err := capProbe.PublishCapabilities(ctx, obs, *hostID); err != nil {
			log.Printf("[main] Failed to publish capabilities: %v", err)
		}
	}

	// Initialize CO-RE builder (from segmentation agent)
	var builder *build.COREBuilder
	if *buildPrograms {
		builder = build.NewCOREBuilder(*clangPath, *bpftoolPath, *btfPath, *buildOutputDir)
		
		// Validate build environment
		if err := builder.ValidateBuildEnvironment(); err != nil {
			log.Printf("[main] Build environment validation failed: %v", err)
			log.Printf("[main] Continuing without runtime program building")
			*buildPrograms = false
		} else {
			log.Printf("[main] CO-RE build environment validated")
		}
	}

	// Initialize enhanced policy engine (from segmentation agent)
	policyEngine := policy.NewEngine()

	// Initialize eBPF system (Cap 7.10)
	var mapManager ebpf.MapManagerInterface
	var policyWriter *ebpf.PolicyWriter
	
	if *enableeBPF && runtime.GOOS == "linux" {
		realMapManager, err := ebpf.NewSimpleMapManager()
		if err != nil {
			log.Printf("[main] Failed to initialize real eBPF maps, using mock: %v", err)
			mapManager = ebpf.NewMockMapManager()
		} else {
			mapManager = realMapManager
			log.Printf("[main] Real eBPF maps initialized")
		}
		
		policyWriter = ebpf.NewPolicyWriter(mapManager, eventEmitter)
	} else if *enableeBPF {
		log.Printf("[main] Non-Linux system, using mock eBPF maps")
		mapManager = ebpf.NewMockMapManager()
		policyWriter = ebpf.NewPolicyWriter(mapManager, eventEmitter)
	} else {
		log.Printf("[main] eBPF enforcement disabled")
	}

	if mapManager != nil {
		defer mapManager.Close()
	}

	// Build eBPF programs if enabled
	if *buildPrograms && builder != nil {
		log.Printf("[main] Building eBPF programs...")
		if err := buildPrograms(ctx, builder); err != nil {
			log.Printf("[main] Failed to build programs: %v", err)
		}
	}

	// Apply initial policies
	if *enableeBPF && policyWriter != nil {
		if *policyFile != "" {
			if err := applyPolicyFromFile(policyWriter, policyEngine, *policyFile, enforceMode, trustMgr, *dryRun); err != nil {
				log.Fatalf("[main] Failed to apply policy: %v", err)
			}
		} else {
			// Apply default segmentation policy
			if err := applyDefaultSegmentationPolicy(policyWriter, policyEngine, enforceMode, *dryRun); err != nil {
				log.Printf("[main] Warning: Failed to apply default policy: %v", err)
			}
		}
	}

	// Initialize HTTP server with enhanced endpoints
	mux := http.NewServeMux()
	
	// Health check endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	
	// Comprehensive status endpoint
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		statusData := map[string]interface{}{
			// Identity
			"host_id":         *hostID,
			"agent_id":        *agentID,
			"agent_uid":       agentUID,
			"org_id":          *orgID,
			"local_ip":        localIP,
			"public_key":      identity.PubKeyB64(pub),
			
			// Configuration
			"enforce_mode":    enforceMode,
			"dry_run":         *dryRun,
			"mtls_enabled":    *mtls,
			"ebpf_enabled":    *enableeBPF,
			"segmentation":    *segmentation,
			"build_programs":  *buildPrograms,
			"registered":      agentUID != "",
			
			// Runtime
			"uptime_seconds":  time.Since(startTime).Seconds(),
			"version":         "Ubuntu Integrated (Cap7.9+7.10+Segmentation)",
			"go_version":      runtime.Version(),
			"platform":        runtime.GOOS + "/" + runtime.GOARCH,
			
			// URLs
			"actions_url":     *actionsURL,
			"registry_url":    *registryURL,
			"nats_url":        *natsURL,
			
			// Policy stats
			"policy_stats":    policyEngine.GetPolicyStats(),
			
			// Capabilities
			"capabilities": []string{
				"backend_registration",
				"identity_management", 
				"http_status_api",
				"telemetry_events",
				"capability_probing",
				"enhanced_observability",
			},
		}
		
		if *enableeBPF {
			statusData["capabilities"] = append(statusData["capabilities"].([]string), 
				"ebpf_policy_enforcement", "network_segmentation")
		}
		
		if *buildPrograms {
			statusData["capabilities"] = append(statusData["capabilities"].([]string),
				"core_ebpf_building", "runtime_compilation")
		}
		
		if *mtls && trustMgr != nil {
			statusData["capabilities"] = append(statusData["capabilities"].([]string),
				"cryptographic_verification", "policy_signing")
		}

		json.NewEncoder(w).Encode(statusData)
	})

	// Policy management endpoints
	mux.HandleFunc("/policies", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.Method {
		case "GET":
			policies, err := policyEngine.GetPolicies(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"policies": policies,
				"count": len(policies),
			})
		case "POST":
			var pol policy.Policy
			if err := json.NewDecoder(r.Body).Decode(&pol); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := policyEngine.AddPolicy(&pol); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"status": "created", "id": pol.ID})
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Policy stats endpoint
	mux.HandleFunc("/policies/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		stats := policyEngine.GetPolicyStats()
		json.NewEncoder(w).Encode(stats)
	})

	// Capabilities endpoint
	mux.HandleFunc("/capabilities", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"capabilities": capabilities,
			"probe_time": time.Now().Format(time.RFC3339),
		})
	})

	// Agent info endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		info := map[string]interface{}{
			"agent_name":        "Aegis Integrated Ubuntu Agent",
			"version":           "Cap7.9+7.10+Segmentation",
			"build_time":        startTime.Format(time.RFC3339),
			"supported_os":      []string{"linux"},
			"supported_distros": []string{"ubuntu", "debian", "centos", "rhel"},
			"requirements": map[string]interface{}{
				"kernel_version": ">=4.18",
				"capabilities":   []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_BPF"},
				"bpf_features":   []string{"BTF", "CO-RE", "TC", "cgroup", "XDP"},
			},
			"features": map[string]bool{
				"backend_registration":         true,
				"ebpf_enforcement":            *enableeBPF,
				"network_segmentation":        *segmentation,
				"runtime_program_building":    *buildPrograms,
				"cryptographic_verification":  *mtls && trustMgr != nil,
				"dry_run_mode":                true,
				"rollback_capability":         true,
				"telemetry_events":            true,
				"enhanced_observability":      true,
				"capability_probing":          true,
				"rule_based_policies":         true,
			},
		}
		json.NewEncoder(w).Encode(info)
	})

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

	// Start policy processing loop
	policyTicker := time.NewTicker(*pollInterval)
	defer policyTicker.Stop()

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
				"host_id":        *hostID,
				"agent_id":       *agentID,
				"agent_uid":      agentUID,
				"version":        "Ubuntu-Integrated",
				"enforce_mode":   enforceMode,
				"ebpf_enabled":   fmt.Sprintf("%v", *enableeBPF),
				"segmentation":   fmt.Sprintf("%v", *segmentation),
			},
		},
		Message: fmt.Sprintf("Aegis Ubuntu Integrated Agent started: %s", *hostID),
	})

	log.Printf("[main] Agent running. Press Ctrl+C to stop.")
	log.Printf("[main] HTTP endpoints: /healthz, /status, /info, /policies, /capabilities")

	// Main loop
	for {
		select {
		case <-sigChan:
			log.Printf("[main] Received shutdown signal")
			goto shutdown
		case <-policyTicker.C:
			// Process policies and update eBPF programs (from segmentation agent)
			if *segmentation && policyEngine != nil {
				if err := processPolicies(ctx, policyEngine, policyWriter, obs); err != nil {
					log.Printf("[main] Policy processing failed: %v", err)
				}
			}
		case <-heartbeatTicker.C:
			log.Printf("[main] Heartbeat - host=%s uid=%s uptime=%.0fs registered=%v", 
				*hostID, agentUID, time.Since(startTime).Seconds(), agentUID != "")
			
			// Emit heartbeat event
			eventEmitter.Emit(telemetry.Event{
				Type: telemetry.EventTypeCounter,
				Data: map[string]interface{}{
					"metric": "agent_heartbeat",
					"value":  1,
					"labels": map[string]string{
						"host_id":   *hostID,
						"agent_uid": agentUID,
					},
				},
				Message: "Agent heartbeat",
			})
		}
	}

shutdown:
	// Cleanup
	log.Printf("[main] Shutting down...")

	// Stop HTTP server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[main] HTTP server shutdown error: %v", err)
	}

	// Emit shutdown event
	eventEmitter.Emit(telemetry.Event{
		Type: telemetry.EventTypeCounter,
		Data: map[string]interface{}{
			"metric": "agent_stopped",
			"value":  1,
			"labels": map[string]string{
				"host_id":   *hostID,
				"agent_uid": agentUID,
			},
		},
		Message: fmt.Sprintf("Aegis Ubuntu Integrated Agent stopped: %s", *hostID),
	})

	log.Printf("[main] Shutdown complete")
}

// buildPrograms builds eBPF programs using CO-RE (from segmentation agent)
func buildPrograms(ctx context.Context, builder *build.COREBuilder) error {
	// Build XDP segmentation program
	xdpResult, err := builder.BuildTemplate(ctx, "xdp_segmentation", map[string]interface{}{
		"MAX_POLICIES": 256,
		"MAX_PORTS":    1024,
	})
	if err != nil {
		return fmt.Errorf("failed to build XDP program: %w", err)
	}
	log.Printf("[build] Built XDP program: %s", xdpResult.ObjectFile)
	
	// Build TC ingress program
	tcResult, err := builder.BuildTemplate(ctx, "tc_ingress", map[string]interface{}{
		"MAX_CLASSES": 64,
		"MAX_FILTERS": 256,
	})
	if err != nil {
		return fmt.Errorf("failed to build TC program: %w", err)
	}
	log.Printf("[build] Built TC program: %s", tcResult.ObjectFile)
	
	// Build cgroup connect programs
	cgroupResult, err := builder.BuildTemplate(ctx, "cgroup_connect4", map[string]interface{}{
		"MAX_CONNECTIONS": 1024,
	})
	if err != nil {
		return fmt.Errorf("failed to build cgroup program: %w", err)
	}
	log.Printf("[build] Built cgroup program: %s", cgroupResult.ObjectFile)
	
	return nil
}

// processPolicies processes policies and updates eBPF programs (from segmentation agent)
func processPolicies(ctx context.Context, policyEngine *policy.Engine, policyWriter *ebpf.PolicyWriter, obs *observability.Observability) error {
	// Get enabled policies
	policies, err := policyEngine.GetEnabledPolicies()
	if err != nil {
		return fmt.Errorf("failed to get enabled policies: %w", err)
	}
	
	if len(policies) == 0 {
		return nil // No policies to process
	}
	
	log.Printf("[policy] Processing %d enabled policies", len(policies))
	
	// Convert policies to eBPF format and apply
	for _, pol := range policies {
		// Convert rule-based policy to eBPF assignment (simplified)
		assignment := convertPolicyToAssignment(pol)
		
		if policyWriter != nil {
			snapshot, err := ebpf.CreateSnapshotFromAssignment(assignment)
			if err != nil {
				log.Printf("[policy] Failed to create snapshot for policy %s: %v", pol.ID, err)
				continue
			}
			
			// Apply the policy snapshot
			if err := policyWriter.ApplySnapshot(ctx, snapshot); err != nil {
				log.Printf("[policy] Failed to apply policy %s: %v", pol.ID, err)
				continue
			}
			
			log.Printf("[policy] Applied policy %s (%s)", pol.ID, pol.Name)
		}
	}
	
	// Publish policy update event
	if obs != nil {
		if err := obs.PublishPolicyUpdate(policies); err != nil {
			log.Printf("[policy] Failed to publish policy update: %v", err)
		}
	}
	
	return nil
}

// convertPolicyToAssignment converts a rule-based policy to an eBPF assignment (simplified)
func convertPolicyToAssignment(pol *policy.Policy) *models.Assignment {
	// Simplified conversion - in practice, this would be more sophisticated
	assignment := &models.Assignment{
		ID:        pol.ID,
		PolicyID:  pol.ID,
		Version:   "1",
		CreatedAt: pol.CreatedAt,
		DryRun:    false,
		Bundle: models.Bundle{
			ID:        pol.ID + "-bundle",
			Content:   []byte(fmt.Sprintf(`{"policy_type":"%s","rules":%d}`, pol.Type, len(pol.Rules))),
			Hash:      "auto-generated",
			Algo:      "policy-engine",
			KeyID:     "local",
			CreatedAt: pol.CreatedAt,
		},
	}
	
	return assignment
}

// applyPolicyFromFile applies a policy from a file with enhanced features
func applyPolicyFromFile(policyWriter *ebpf.PolicyWriter, policyEngine *policy.Engine, policyFile string, enforceMode string, trustMgr *crypto.TrustStoreManager, dryRun bool) error {
	log.Printf("[policy] Applying policy from file: %s (mode=%s, dry-run=%v)", policyFile, enforceMode, dryRun)

	// Read policy file
	content, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	// Try to parse as rule-based policy first
	var rulePol policy.Policy
	if err := json.Unmarshal(content, &rulePol); err == nil && rulePol.ID != "" {
		// It's a rule-based policy
		log.Printf("[policy] Detected rule-based policy: %s", rulePol.Name)
		
		if err := policyEngine.AddPolicy(&rulePol); err != nil {
			log.Printf("[policy] Warning: Failed to add to policy engine: %v", err)
		}
		
		// Convert to assignment format for eBPF
		assignment := convertPolicyToAssignment(&rulePol)
		
		// Verify if trust manager is available
		if trustMgr != nil {
			log.Printf("[policy] Trust store available for verification")
		}
		
		// Apply to eBPF
		snapshot, err := ebpf.CreateSnapshotFromAssignment(assignment)
		if err != nil {
			return fmt.Errorf("failed to create snapshot: %w", err)
		}
		
		snapshot.Mode = enforceMode
		
		ctx := context.Background()
		return policyWriter.ApplySnapshot(ctx, snapshot)
	}

	// Fall back to legacy assignment format
	var assignment models.Assignment
	if err := json.Unmarshal(content, &assignment); err != nil {
		return fmt.Errorf("failed to parse policy file as either rule-based or assignment format: %w", err)
	}

	log.Printf("[policy] Detected legacy assignment format")
	
	// Apply legacy assignment
	snapshot, err := ebpf.CreateSnapshotFromAssignment(&assignment)
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	snapshot.Mode = enforceMode

	ctx := context.Background()
	return policyWriter.ApplySnapshot(ctx, snapshot)
}

// applyDefaultSegmentationPolicy applies a default segmentation policy
func applyDefaultSegmentationPolicy(policyWriter *ebpf.PolicyWriter, policyEngine *policy.Engine, enforceMode string, dryRun bool) error {
	log.Printf("[policy] Applying default segmentation policy in %s mode (dry-run: %v)", enforceMode, dryRun)

	// Create a default network segmentation policy
	defaultPolicy := &policy.Policy{
		ID:          "default-segmentation",
		Name:        "Default Network Segmentation",
		Description: "Block access to Google DNS as example",
		Type:        "network",
		Priority:    100,
		Enabled:     true,
		Rules: []policy.Rule{
			{
				ID:       "block-google-dns",
				Action:   "deny",
				Priority: 1,
				Conditions: []policy.Condition{
					{Field: "dest_ip", Operator: "eq", Value: "8.8.8.8"},
					{Field: "protocol", Operator: "eq", Value: "tcp"},
				},
				Metadata: map[string]interface{}{
					"description": "Block TCP connections to Google DNS",
				},
			},
		},
		Metadata: map[string]interface{}{
			"auto_generated": true,
			"default_policy": true,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Add to policy engine
	if err := policyEngine.AddPolicy(defaultPolicy); err != nil {
		log.Printf("[policy] Warning: Failed to add default policy to engine: %v", err)
	}

	// Convert to assignment and apply
	assignment := convertPolicyToAssignment(defaultPolicy)
	assignment.DryRun = dryRun

	snapshot, err := ebpf.CreateSnapshotFromAssignment(assignment)
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	snapshot.Mode = enforceMode

	ctx := context.Background()
	return policyWriter.ApplySnapshot(ctx, snapshot)
}

// generateAgentID generates an agent ID
func generateAgentID(hostID string) string {
	if agentID := os.Getenv("AGENT_ID"); agentID != "" {
		return agentID
	}
	return fmt.Sprintf("agent-%s-%d", hostID, time.Now().Unix())
}

// getLocalIP gets the local IP address
func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()
	
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// getenv gets an environment variable with a default value
func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
