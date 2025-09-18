package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"agents/local-agent-go/internal/capability"
	"agents/local-agent-go/internal/drift"
	"agents/local-agent-go/internal/guard"
	"agents/local-agent-go/internal/loader"
	"agents/local-agent-go/internal/policy"
	"agents/local-agent-go/internal/registry"
	"agents/local-agent-go/internal/seg"
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

func getProjectRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		log.Printf("Failed to get working directory: %v", err)
		return "."
	}
	
	// Find the project root by looking for the bpf directory
	projectRoot := wd
	for {
		if _, err := os.Stat(filepath.Join(projectRoot, "bpf")); err == nil {
			break
		}
		parent := filepath.Dir(projectRoot)
		if parent == projectRoot {
			log.Printf("Could not find bpf directory, using current directory")
			return wd
		}
		projectRoot = parent
	}
	
	return projectRoot
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
	verifyMode := verify.ParseVerificationMode(getenv("AGENT_VERIFY", "strict"))
	verifier, err := verify.NewVerifier(vaultURL, vaultToken, devPubKeyPath, verifyMode)
	if err != nil {
		log.Fatalf("Failed to initialize verifier: %v", err)
	}
	log.Printf("[agent] Signature verification mode: %s", verifier.GetMode())

	// Initialize policy writer
	policyWriter, err := policy.NewWriter()
	if err != nil {
		log.Fatalf("Failed to initialize policy writer: %v", err)
	}
	defer policyWriter.Close()

	// Initialize eBPF loader
	ebpfLoader := loader.NewLoader()
	defer ebpfLoader.Close()
	
	// Initialize segmentation loaders
	segEgressLoader := loader.NewSegEgressLoader()
	defer segEgressLoader.Close()
	
	segIngressLoader := loader.NewSegIngressLoader()
	defer segIngressLoader.Close()
	
	// Load segmentation eBPF programs
	projectRoot := getProjectRoot()
	egressObjectPath := filepath.Join(projectRoot, "bpf", "bpf", "seg_egress_cgroup.o")
	ingressObjectPath := filepath.Join(projectRoot, "bpf", "bpf", "seg_ingress_tc.o")
	
	// Load egress program
	if err := segEgressLoader.LoadProgram(context.Background(), egressObjectPath); err != nil {
		log.Printf("[agent] failed to load egress segmentation program: %v", err)
	} else {
		log.Printf("[agent] loaded egress segmentation program from %s", egressObjectPath)
	}
	
	// Load ingress program
	if err := segIngressLoader.LoadProgram(context.Background(), ingressObjectPath); err != nil {
		log.Printf("[agent] failed to load ingress segmentation program: %v", err)
	} else {
		log.Printf("[agent] loaded ingress segmentation program from %s", ingressObjectPath)
	}

	// Initialize capability probe
	capProbe := capability.New()

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
		_ = tel.EmitRolledBack(artifactID, "cpu_guard")
		
		// Rollback to previous generation
		rollbackArtifacts := stat.RollbackToPreviousGeneration()
		log.Printf("[agent] Rolled back to generation %d, artifacts: %v", stat.GetActiveGeneration(), rollbackArtifacts)
		
		// Unload current generation programs
		return ebpfLoader.UnloadProgram(context.Background(), artifactID)
	})
	
	// Start CPU watcher
	cpuWatcher.Start(context.Background())
	defer cpuWatcher.Stop()

	mux := http.NewServeMux()
	status.RegisterHandlers(mux, stat, verifier, segEgressLoader, segIngressLoader, cpuWatcher)
	srv := &http.Server{Addr: httpAddr, Handler: mux}
	go func() {
		log.Printf("[agent] status server listening on %s", httpAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)

	// Initialize policy subscriber
	policySubject := getenv("AGENT_POLICY_SUBJECT", "aegis.policy.updates")
	subscriber := seg.NewSubscriber(tel.GetConn(), policyWriter, policySubject)
	go func() {
		if err := subscriber.Start(ctx); err != nil {
			log.Printf("[agent] policy subscriber error: %v", err)
		}
	}()
	log.Printf("[agent] policy subscriber started on subject: %s", policySubject)
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
				
				// Verify signature before loading
				if bundlePath != "" {
					// Read bundle data for verification
					bundleData, err := os.ReadFile(bundlePath)
					if err != nil {
						log.Printf("[agent] failed to read bundle file %s: %v", bundlePath, err)
						_ = tel.EmitError(a.ArtifactID, fmt.Sprintf("failed to read bundle file: %v", err))
						continue
					}
					
					// Verify bundle signature
					if err := verifier.VerifyBundle(bundleData, a.Signature); err != nil {
						log.Printf("[agent] signature verification failed for %s: %v", a.ArtifactID, err)
						_ = tel.EmitError(a.ArtifactID, fmt.Sprintf("signature verification failed: %v", err))
						continue
					}
					log.Printf("[agent] signature verification successful for %s", a.ArtifactID)
				} else if a.Signature != "" {
					// Verify signature of artifact metadata
					artifactData := []byte(fmt.Sprintf("artifact:%s", a.ArtifactID))
					if err := verifier.VerifyBundle(artifactData, a.Signature); err != nil {
						log.Printf("[agent] signature verification failed for %s: %v", a.ArtifactID, err)
						_ = tel.EmitError(a.ArtifactID, fmt.Sprintf("signature verification failed: %v", err))
						continue
					}
					log.Printf("[agent] signature verification successful for %s", a.ArtifactID)
				}
				
				// Load eBPF program if bundle is available
				if bundlePath != "" {
					// Increment generation for new artifacts
					currentGen := stat.IncrementGeneration()
					log.Printf("[agent] Loading artifact %s in generation %d", a.ArtifactID, currentGen)
					
					programName := a.ArtifactID // Use artifact ID as program name
					progInfo, err := ebpfLoader.LoadProgram(ctx, bundlePath, programName)
					if err != nil {
						log.Printf("[agent] failed to load eBPF program for %s: %v", a.ArtifactID, err)
						_ = tel.EmitError(a.ArtifactID, fmt.Sprintf("eBPF program loading failed: %v", err))
						continue
					}
					log.Printf("[agent] loaded eBPF program %s: %+v", a.ArtifactID, progInfo)
					
					// Example: Attach to cgroup if it's a cgroup program
					if contains(programName, "cgroup") {
						cgroupPath := getenv("AGENT_CGROUP_PATH", "/sys/fs/cgroup/aegis")
						if contains(programName, "connect4") {
							if err := segEgressLoader.AttachCgroupConnect4(context.Background(), cgroupPath); err != nil {
								log.Printf("[agent] failed to attach cgroup connect4 for %s: %v", a.ArtifactID, err)
							} else {
								log.Printf("[agent] attached cgroup connect4 for %s to %s", a.ArtifactID, cgroupPath)
							}
						} else if contains(programName, "connect6") {
							if err := segEgressLoader.AttachCgroupConnect6(context.Background(), cgroupPath); err != nil {
								log.Printf("[agent] failed to attach cgroup connect6 for %s: %v", a.ArtifactID, err)
							} else {
								log.Printf("[agent] attached cgroup connect6 for %s to %s", a.ArtifactID, cgroupPath)
							}
						}
					}
					
					// Example: Attach to TC ingress if it's a TC program
					if contains(programName, "tc") || contains(programName, "ingress") {
						iface := getenv("AGENT_INTERFACE", "eth0")
						if err := segIngressLoader.AttachTCClassifier(context.Background(), iface); err != nil {
							log.Printf("[agent] failed to attach TC classifier for %s: %v", a.ArtifactID, err)
						} else {
							log.Printf("[agent] attached TC classifier for %s to %s", a.ArtifactID, iface)
						}
					}
					
					// Register for drift detection
					driftDetector.RegisterArtifact(a.ArtifactID, bundlePath, 30*time.Minute)
					
					// Start CPU monitoring (simulate process ID)
					cpuWatcher.WatchArtifact(a.ArtifactID, os.Getpid())
					
					// Add to current generation
					stat.AddToGeneration(a.ArtifactID, currentGen)
				}
				
				_ = tel.EmitLoaded(a.ArtifactID)
				stat.TrackLoaded(a.ArtifactID, time.Now().Add(30*time.Minute))
			}
		}
	}
}
