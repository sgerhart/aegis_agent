package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"agents/segmentation-agent-go/internal/build"
	"agents/segmentation-agent-go/internal/capability"
	"agents/segmentation-agent-go/internal/loader"
	"agents/segmentation-agent-go/internal/observability"
	"agents/segmentation-agent-go/internal/policy"
)

func main() {
	// Environment variables
	hostID := getenv("AGENT_HOST_ID", "segmentation-host-unknown")
	natsURL := getenv("NATS_URL", "nats://localhost:4222")
	httpAddr := getenv("AGENT_HTTP_ADDR", ":8080")
	pollInterval, _ := time.ParseDuration(getenv("AGENT_POLL_INTERVAL", "30s"))
	
	// Initialize components
	capProbe := capability.NewProbe()
	obs := observability.New(natsURL, hostID)
	policyEngine := policy.NewEngine()
	
	// Initialize CO-RE builder
	builder := build.NewCOREBuilder(
		getenv("CLANG_PATH", "clang"),
		getenv("BPFTOOL_PATH", "bpftool"),
		getenv("BTF_PATH", "/sys/kernel/btf/vmlinux"),
		getenv("BUILD_OUTPUT_DIR", "./build"),
	)
	
	// Validate build environment
	if err := builder.ValidateBuildEnvironment(); err != nil {
		log.Fatalf("Build environment validation failed: %v", err)
	}
	
	// Initialize eBPF loader
	ebpfLoader := loader.NewLoader()
	defer ebpfLoader.Close()
	
	// HTTP server for health checks
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		status := map[string]interface{}{
			"host_id": hostID,
			"status":  "running",
			"time":    time.Now().UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"host_id":"%s","status":"%s","time":"%s"}`, 
			status["host_id"], status["status"], status["time"])
	})
	
	srv := &http.Server{Addr: httpAddr, Handler: mux}
	go func() {
		log.Printf("[agent] HTTP server starting on %s", httpAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()
	
	// Context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	
	// Probe system capabilities
	log.Printf("[agent] probing system capabilities...")
	capabilities, err := capProbe.ProbeCapabilities(ctx)
	if err != nil {
		log.Printf("[agent] capability probe failed: %v", err)
	} else {
		log.Printf("[agent] capabilities: %+v", capabilities)
		
		// Publish capabilities to NATS
		if err := capProbe.PublishCapabilities(ctx, obs, hostID); err != nil {
			log.Printf("[agent] failed to publish capabilities: %v", err)
		}
	}
	
	// Build eBPF programs
	log.Printf("[agent] building eBPF programs...")
	if err := buildPrograms(ctx, builder); err != nil {
		log.Printf("[agent] failed to build programs: %v", err)
	}
	
	// Main loop
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	
	log.Printf("[agent] segmentation agent starting; host_id=%s", hostID)
	
	for {
		select {
		case <-ctx.Done():
			log.Printf("[agent] shutting down")
			_ = srv.Shutdown(context.Background())
			return
		case <-ticker.C:
			// Process policies and update eBPF programs
			if err := processPolicies(ctx, policyEngine, ebpfLoader, obs); err != nil {
				log.Printf("[agent] policy processing failed: %v", err)
			}
			
			// Collect and publish metrics
			if err := collectMetrics(ctx, ebpfLoader, obs); err != nil {
				log.Printf("[agent] metrics collection failed: %v", err)
			}
		}
	}
}

func getenv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func buildPrograms(ctx context.Context, builder *build.COREBuilder) error {
	// Build XDP segmentation program
	xdpResult, err := builder.BuildTemplate(ctx, "xdp_segmentation", map[string]interface{}{
		"MAX_POLICIES": 256,
		"MAX_PORTS":    1024,
	})
	if err != nil {
		return fmt.Errorf("failed to build XDP program: %w", err)
	}
	log.Printf("[agent] built XDP program: %s", xdpResult.ObjectFile)
	
	// Build TC ingress program
	tcResult, err := builder.BuildTemplate(ctx, "tc_ingress", map[string]interface{}{
		"MAX_CLASSES": 64,
		"MAX_FILTERS": 256,
	})
	if err != nil {
		return fmt.Errorf("failed to build TC program: %w", err)
	}
	log.Printf("[agent] built TC program: %s", tcResult.ObjectFile)
	
	return nil
}

func processPolicies(ctx context.Context, policyEngine *policy.Engine, loader *loader.Loader, obs *observability.Observability) error {
	// Get current policies
	policies, err := policyEngine.GetPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to get policies: %w", err)
	}
	
	// Update eBPF maps with new policies
	for _, pol := range policies {
		if err := loader.UpdatePolicy(pol); err != nil {
			log.Printf("[agent] failed to update policy %s: %v", pol.ID, err)
			continue
		}
	}
	
	// Publish policy update event
	if err := obs.PublishPolicyUpdate(policies); err != nil {
		log.Printf("[agent] failed to publish policy update: %v", err)
	}
	
	return nil
}

func collectMetrics(ctx context.Context, loader *loader.Loader, obs *observability.Observability) error {
	// Collect eBPF program statistics
	stats, err := loader.CollectStats()
	if err != nil {
		return fmt.Errorf("failed to collect stats: %w", err)
	}
	
	// Publish metrics
	if err := obs.PublishMetrics(stats); err != nil {
		return fmt.Errorf("failed to publish metrics: %w", err)
	}
	
	return nil
}
