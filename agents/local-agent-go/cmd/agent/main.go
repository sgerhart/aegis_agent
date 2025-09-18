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

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
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
	
	// Initialize segmentation loader
	segLoader := loader.NewSegmentationLoader()
	defer segLoader.Close()

	// Initialize capability probe
	capProbe := capability.NewProbe()

	// Initialize drift detector
	driftDetector := drift.NewDetector()

	// Initialize CPU watcher
	maxCPUPercent := 3.0 // Default 3% as per prompt
	if envCPU := getenv("AGENT_CPU_MAX", ""); envCPU != "" {
		if parsed, err := time.ParseDuration(envCPU); err == nil {
			maxCPUPercent = parsed.Seconds()
		}
	}
	
	cpuWatcher := guard.NewCPUWatcher(maxCPUPercent, 5*time.Second, func(artifactID string) error {
		log.Printf("[agent] CPU threshold exceeded, rolling back artifact %s", artifactID)
		_ = tel.EmitRolledBack(artifactID, "CPU threshold exceeded")
		return ebpfLoader.UnloadProgram(context.Background(), artifactID)
	})
	
	// Start CPU watcher
	cpuWatcher.Start(ctx)
	defer cpuWatcher.Stop()

	mux := http.NewServeMux()
	status.RegisterHandlers(mux, stat, verifier, segLoader)
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
					
					// Load program in segmentation loader for advanced attachment
					segProg, err := segLoader.LoadProgram(ctx, bundlePath, programName)
					if err != nil {
						log.Printf("[agent] failed to load program in segmentation loader for %s: %v", a.ArtifactID, err)
					} else {
						// Pin maps for atomic updates
						if err := segLoader.PinMaps(); err != nil {
							log.Printf("[agent] failed to pin maps for %s: %v", a.ArtifactID, err)
						}
						
						// Example: Attach to cgroup if it's a cgroup program
						if contains(programName, "cgroup") {
							cgroupPath := getenv("AGENT_CGROUP_PATH", "/sys/fs/cgroup/aegis")
							if contains(programName, "connect4") {
								if err := segLoader.AttachCgroupConnect4(ctx, programName, cgroupPath); err != nil {
									log.Printf("[agent] failed to attach cgroup connect4 for %s: %v", a.ArtifactID, err)
								} else {
									log.Printf("[agent] attached cgroup connect4 for %s to %s", a.ArtifactID, cgroupPath)
								}
							} else if contains(programName, "connect6") {
								if err := segLoader.AttachCgroupConnect6(ctx, programName, cgroupPath); err != nil {
									log.Printf("[agent] failed to attach cgroup connect6 for %s: %v", a.ArtifactID, err)
								} else {
									log.Printf("[agent] attached cgroup connect6 for %s to %s", a.ArtifactID, cgroupPath)
								}
							}
						}
						
						// Example: Attach to TC ingress if it's a TC program
						if contains(programName, "tc") || contains(programName, "ingress") {
							iface := getenv("AGENT_INTERFACE", "eth0")
							if err := segLoader.AttachTCIngress(ctx, programName, iface); err != nil {
								log.Printf("[agent] failed to attach TC ingress for %s: %v", a.ArtifactID, err)
							} else {
								log.Printf("[agent] attached TC ingress for %s to %s", a.ArtifactID, iface)
							}
						}
						
						// Example: Attach to XDP if it's an XDP program
						if contains(programName, "xdp") {
							iface := getenv("AGENT_INTERFACE", "eth0")
							if err := segLoader.AttachXDP(ctx, programName, iface); err != nil {
								log.Printf("[agent] failed to attach XDP for %s: %v", a.ArtifactID, err)
							} else {
								log.Printf("[agent] attached XDP for %s to %s", a.ArtifactID, iface)
							}
						}
					}
					
					// Register for drift detection
					driftDetector.RegisterArtifact(a.ArtifactID, bundlePath, 30*time.Minute)
					
					// Start CPU monitoring (simulate process ID)
					cpuWatcher.WatchArtifact(a.ArtifactID, os.Getpid())
				}
				
				_ = tel.EmitLoaded(a.ArtifactID)
				stat.TrackLoaded(a.ArtifactID, time.Now().Add(30*time.Minute))
			}
		}
	}
}
