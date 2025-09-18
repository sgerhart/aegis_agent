package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"agents/local-agent-go/internal/guard"
	"agents/local-agent-go/internal/status"
	"agents/local-agent-go/internal/telemetry"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutdown signal received")
		cancel()
	}()

	fmt.Println("=== AegisFlux CPU Guard Rollback Demo ===")
	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	// Create telemetry (mock NATS)
	tel := telemetry.New("nats://localhost:4222", "demo-host")
	defer tel.Close()

	// Create status tracker
	stat := status.New()

	// Create CPU watcher with very low threshold for demonstration
	maxCPUPercent := 0.5 // Very low threshold to trigger easily
	cpuWatcher := guard.NewCPUWatcher(maxCPUPercent, 1*time.Second, func(artifactID string) error {
		log.Printf("[cpu-guard] 🚨 CPU threshold exceeded! Rolling back artifact %s", artifactID)
		
		// Emit rollback telemetry
		_ = tel.EmitRolledBack(artifactID, "cpu_guard")
		
		// Rollback to previous generation
		rollbackArtifacts := stat.RollbackToPreviousGeneration()
		log.Printf("[cpu-guard] ✅ Rolled back to generation %d, restored artifacts: %v", 
			stat.GetActiveGeneration(), rollbackArtifacts)
		
		return nil
	})

	// Start CPU watcher
	cpuWatcher.Start(ctx)
	defer cpuWatcher.Stop()

	fmt.Printf("✓ CPU watcher started with threshold: %.1f%%\n", maxCPUPercent)

	// Simulate loading artifacts in different generations
	fmt.Println("\n=== Loading Artifacts in Generations ===")

	// Generation 1 - Base artifacts
	gen1 := stat.IncrementGeneration()
	artifacts1 := []string{"base-policy", "monitoring"}
	for _, artifact := range artifacts1 {
		stat.AddToGeneration(artifact, gen1)
		stat.TrackLoaded(artifact, time.Now().Add(30*time.Minute))
		cpuWatcher.WatchArtifact(artifact, os.Getpid())
		fmt.Printf("  ✓ Loaded %s in generation %d\n", artifact, gen1)
	}

	time.Sleep(2 * time.Second)

	// Generation 2 - New features
	gen2 := stat.IncrementGeneration()
	artifacts2 := []string{"advanced-filtering", "real-time-analytics"}
	for _, artifact := range artifacts2 {
		stat.AddToGeneration(artifact, gen2)
		stat.TrackLoaded(artifact, time.Now().Add(30*time.Minute))
		cpuWatcher.WatchArtifact(artifact, os.Getpid())
		fmt.Printf("  ✓ Loaded %s in generation %d\n", artifact, gen2)
	}

	time.Sleep(2 * time.Second)

	// Generation 3 - Experimental features
	gen3 := stat.IncrementGeneration()
	artifacts3 := []string{"experimental-ml", "beta-features"}
	for _, artifact := range artifacts3 {
		stat.AddToGeneration(artifact, gen3)
		stat.TrackLoaded(artifact, time.Now().Add(30*time.Minute))
		cpuWatcher.WatchArtifact(artifact, os.Getpid())
		fmt.Printf("  ✓ Loaded %s in generation %d\n", artifact, gen3)
	}

	// Show current status
	fmt.Println("\n=== Current System Status ===")
	fmt.Printf("Active generation: %d\n", stat.GetActiveGeneration())
	fmt.Printf("Total loaded artifacts: %d\n", len(stat.GetGenerationArtifacts(stat.GetActiveGeneration())))
	fmt.Printf("Watched artifacts: %d\n", len(cpuWatcher.GetWatchedArtifacts()))

	// Show generation breakdown
	for gen := int64(1); gen <= stat.GetActiveGeneration(); gen++ {
		artifacts := stat.GetGenerationArtifacts(gen)
		fmt.Printf("  Generation %d: %v\n", gen, artifacts)
	}

	// Show CPU watcher stats
	fmt.Println("\n=== CPU Watcher Statistics ===")
	stats := cpuWatcher.GetStats()
	fmt.Printf("  Max CPU threshold: %.1f%%\n", stats["max_cpu_percent"])
	fmt.Printf("  Sample interval: %v\n", stats["sample_interval"])
	fmt.Printf("  Watched artifacts: %d\n", stats["watched_artifacts"])

	// Simulate high CPU usage to trigger rollback
	fmt.Println("\n=== Simulating High CPU Load ===")
	fmt.Println("Starting CPU-intensive operations to trigger rollback...")
	
	// Start multiple CPU-intensive goroutines
	for i := 0; i < runtime.NumCPU(); i++ {
		go func(id int) {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					// CPU-intensive operation
					for j := 0; j < 100000; j++ {
						_ = j * j * j
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}(i)
	}

	// Monitor for rollbacks
	fmt.Println("Monitoring for CPU threshold violations...")
	
	// Wait and monitor
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		
		// Check if rollback occurred
		currentGen := stat.GetActiveGeneration()
		if currentGen < gen3 {
			fmt.Printf("🔄 Rollback detected! Current generation: %d\n", currentGen)
			break
		}
		
		// Show current CPU stats
		artifacts := stats["artifacts"].(map[string]interface{})
		for artifactID, artifactStats := range artifacts {
			stats := artifactStats.(map[string]interface{})
			cpu := stats["avg_cpu"].(float64)
			fmt.Printf("  %s: %.2f%% CPU\n", artifactID, cpu)
		}
	}

	// Show final status
	fmt.Println("\n=== Final System Status ===")
	fmt.Printf("Active generation: %d\n", stat.GetActiveGeneration())
	fmt.Printf("Total loaded artifacts: %d\n", len(stat.GetGenerationArtifacts(stat.GetActiveGeneration())))

	// Show generation breakdown after potential rollback
	for gen := int64(1); gen <= stat.GetActiveGeneration(); gen++ {
		artifacts := stat.GetGenerationArtifacts(gen)
		status := "active"
		if gen < stat.GetActiveGeneration() {
			status = "rolled back"
		}
		fmt.Printf("  Generation %d (%s): %v\n", gen, status, artifacts)
	}

	// Show final CPU watcher stats
	fmt.Println("\n=== Final CPU Watcher Statistics ===")
	stats = cpuWatcher.GetStats()
	artifacts := stats["artifacts"].(map[string]interface{})
	for artifactID, artifactStats := range artifacts {
		stats := artifactStats.(map[string]interface{})
		cpu := stats["avg_cpu"].(float64)
		rollbacks := stats["rollback_count"].(int)
		fmt.Printf("  %s: %.2f%% CPU, %d rollbacks\n", artifactID, cpu, rollbacks)
	}

	fmt.Println("\n=== Demo Summary ===")
	fmt.Println("✓ CPU watcher with rollback mechanism")
	fmt.Println("✓ Generation-based artifact management")
	fmt.Println("✓ Automatic rollback on CPU threshold violation")
	fmt.Println("✓ Telemetry integration for rollback events")
	fmt.Println("✓ Status tracking with active generation")
	fmt.Println("✓ Multi-generation artifact support")

	// Keep running until shutdown
	<-ctx.Done()
	fmt.Println("Demo completed")
}
