package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"agents/local-agent-go/internal/capability"
	"agents/local-agent-go/internal/drift"
	"agents/local-agent-go/internal/guard"
	"agents/local-agent-go/internal/loader"
	"agents/local-agent-go/internal/registry"
	"agents/local-agent-go/internal/status"
	"agents/local-agent-go/internal/telemetry"
	"agents/local-agent-go/internal/verify"
)

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	regURL := getenv("AGENT_REGISTRY_URL", "http://localhost:8090")
	natsURL := getenv("NATS_URL", "nats://localhost:4222")
	hostID := getenv("AGENT_HOST_ID", "host-unknown")
	pollEvery, _ := time.ParseDuration(getenv("AGENT_POLL_INTERVAL", "10s"))
	httpAddr := getenv("AGENT_HTTP_ADDR", ":7070")
	vaultURL := getenv("VAULT_URL", "")
	vaultToken := getenv("VAULT_TOKEN", "")
	devPubKeyPath := getenv("DEV_PUBLIC_KEY_PATH", "")
	driftCheckInterval, _ := time.ParseDuration(getenv("DRIFT_CHECK_INTERVAL", "30s"))

	reg := registry.NewClient(regURL, hostID)
	tel := telemetry.New(natsURL, hostID)
	stat := status.New()
	
	// Initialize signature verifier
	verifier, err := verify.NewVerifier(vaultURL, vaultToken, devPubKeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize verifier: %v", err)
	}

	// Initialize eBPF loader
	ebpfLoader := loader.NewLoader()
	defer ebpfLoader.Close()

	// Initialize capability probe
	capProbe := capability.NewProbe()

	// Initialize drift detector
	driftDetector := drift.NewDetector()

	// Initialize CPU guard
	cpuGuard := guard.NewCPUGuard(80.0, 10*time.Second, func(artifactID string) error {
		log.Printf("[agent] CPU threshold exceeded, rolling back artifact %s", artifactID)
		_ = tel.EmitRolledBack(artifactID, "CPU threshold exceeded")
		return ebpfLoader.UnloadProgram(context.Background(), artifactID)
	})

	mux := http.NewServeMux()
	status.RegisterHandlers(mux, stat)
	srv := &http.Server{Addr: httpAddr, Handler: mux}
	go func() {
		log.Printf("[agent] status server listening on %s", httpAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	t := time.NewTicker(pollEvery)
	defer t.Stop()

	log.Printf("[agent] starting; host_id=%s registry=%s nats=%s", hostID, regURL, natsURL)
	
	// Probe system capabilities
	capabilities, err := capProbe.ProbeCapabilities(ctx)
	if err != nil {
		log.Printf("[agent] capability probe failed: %v", err)
	} else {
		log.Printf("[agent] system capabilities: BTF=%v, BPF features=%v", capabilities.BTFAvailable, capabilities.BPFFeatures)
		// Publish capabilities
		_ = capProbe.PublishCapabilities(ctx, tel, hostID)
	}
	
	// Start drift detection
	go driftDetector.StartPeriodicCheck(ctx, driftCheckInterval, func(artifactID string) error {
		log.Printf("[agent] drift detected for artifact %s", artifactID)
		_ = tel.EmitError(artifactID, "drift detected")
		// Unload the program
		return ebpfLoader.UnloadProgram(ctx, artifactID)
	})

	for {
		select {
		case <-ctx.Done():
			log.Printf("[agent] shutting down")
			_ = srv.Shutdown(context.Background())
			return
		case <-t.C:
			assignments, err := reg.FetchAssignments(ctx)
			if err != nil {
				log.Printf("[agent] registry fetch: %v", err)
				continue
			}
			for _, a := range assignments {
				log.Printf("[agent] assignment: %+v", a)
				
				// Download bundle if URL is provided
				var bundlePath string
				if a.BundleURL != "" {
					bundlesDir := getenv("AGENT_BUNDLES_DIR", "./bundles")
					var err error
					bundlePath, err = reg.DownloadBundle(ctx, a, bundlesDir)
					if err != nil {
						log.Printf("[agent] failed to download bundle for %s: %v", a.ArtifactID, err)
						_ = tel.EmitError(a.ArtifactID, fmt.Sprintf("bundle download failed: %v", err))
						continue
					}
					log.Printf("[agent] downloaded bundle for %s to %s", a.ArtifactID, bundlePath)
				}
				
				// Verify signature if provided
				if a.Signature != "" && a.SignatureAlg != "" {
					sigData := verify.SignatureData{
						Signature: a.Signature,
						Algorithm: a.SignatureAlg,
						KeyID:     a.KeyID,
					}
					
					if bundlePath != "" {
						// Verify signature of downloaded bundle
						if err := verifier.VerifyBundleSignature(ctx, bundlePath, sigData); err != nil {
							log.Printf("[agent] signature verification failed for %s: %v", a.ArtifactID, err)
							_ = tel.EmitError(a.ArtifactID, fmt.Sprintf("signature verification failed: %v", err))
							continue
						}
					} else {
						// Verify signature of artifact metadata
						artifactData := []byte(fmt.Sprintf("artifact:%s", a.ArtifactID))
						if err := verifier.VerifySignature(ctx, artifactData, sigData); err != nil {
							log.Printf("[agent] signature verification failed for %s: %v", a.ArtifactID, err)
							_ = tel.EmitError(a.ArtifactID, fmt.Sprintf("signature verification failed: %v", err))
							continue
						}
					}
					log.Printf("[agent] signature verification successful for %s", a.ArtifactID)
				}
				
				// Load eBPF program if bundle is available
				if bundlePath != "" {
					programName := a.ArtifactID // Use artifact ID as program name
					progInfo, err := ebpfLoader.LoadProgram(ctx, bundlePath, programName)
					if err != nil {
						log.Printf("[agent] failed to load eBPF program for %s: %v", a.ArtifactID, err)
						_ = tel.EmitError(a.ArtifactID, fmt.Sprintf("eBPF program loading failed: %v", err))
						continue
					}
					log.Printf("[agent] loaded eBPF program %s: %+v", a.ArtifactID, progInfo)
					
					// Register for drift detection
					driftDetector.RegisterArtifact(a.ArtifactID, bundlePath, 30*time.Minute)
					
					// Start CPU monitoring (simulate process ID)
					cpuGuard.StartMonitoring(ctx, a.ArtifactID, os.Getpid())
				}
				
				_ = tel.EmitLoaded(a.ArtifactID)
				stat.TrackLoaded(a.ArtifactID, time.Now().Add(30*time.Minute))
			}
		}
	}
}
