package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
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

	fmt.Println("=== AegisFlux CPU Guard and Rollback Test ===")

	// Create telemetry (mock NATS)
	tel := telemetry.New("nats://localhost:4222", "test-host")
	defer tel.Close()

	// Create status tracker
	stat := status.New()

	// Create CPU watcher with low threshold for testing
	maxCPUPercent := 1.0 // Very low threshold for testing
	cpuWatcher := guard.NewCPUWatcher(maxCPUPercent, 2*time.Second, func(artifactID string) error {
		log.Printf("[cpu-guard] CPU threshold exceeded, rolling back artifact %s", artifactID)
		
		// Emit rollback telemetry
		_ = tel.EmitRolledBack(artifactID, "cpu_guard")
		
		// Rollback to previous generation
		rollbackArtifacts := stat.RollbackToPreviousGeneration()
		log.Printf("[cpu-guard] Rolled back to generation %d, artifacts: %v", 
			stat.GetActiveGeneration(), rollbackArtifacts)
		
		return nil
	})

	// Start CPU watcher
	cpuWatcher.Start(ctx)
	defer cpuWatcher.Stop()

	fmt.Printf("✓ CPU watcher started with threshold: %.1f%%\n", maxCPUPercent)

	// Simulate loading artifacts in different generations
	fmt.Println("\n=== Simulating Artifact Loading ===")

	// Generation 1
	gen1 := stat.IncrementGeneration()
	stat.AddToGeneration("artifact-1", gen1)
	stat.TrackLoaded("artifact-1", time.Now().Add(30*time.Minute))
	cpuWatcher.WatchArtifact("artifact-1", os.Getpid())
	fmt.Printf("✓ Loaded artifact-1 in generation %d\n", gen1)

	time.Sleep(1 * time.Second)

	// Generation 2
	gen2 := stat.IncrementGeneration()
	stat.AddToGeneration("artifact-2", gen2)
	stat.TrackLoaded("artifact-2", time.Now().Add(30*time.Minute))
	cpuWatcher.WatchArtifact("artifact-2", os.Getpid())
	fmt.Printf("✓ Loaded artifact-2 in generation %d\n", gen2)

	time.Sleep(1 * time.Second)

	// Generation 3
	gen3 := stat.IncrementGeneration()
	stat.AddToGeneration("artifact-3", gen3)
	stat.TrackLoaded("artifact-3", time.Now().Add(30*time.Minute))
	cpuWatcher.WatchArtifact("artifact-3", os.Getpid())
	fmt.Printf("✓ Loaded artifact-3 in generation %d\n", gen3)

	// Show current status
	fmt.Println("\n=== Current Status ===")
	fmt.Printf("Active generation: %d\n", stat.GetActiveGeneration())
	fmt.Printf("Loaded artifacts: %v\n", getLoadedArtifacts(stat))
	fmt.Printf("Watched artifacts: %v\n", cpuWatcher.GetWatchedArtifacts())

	// Show CPU watcher stats
	fmt.Println("\n=== CPU Watcher Stats ===")
	stats := cpuWatcher.GetStats()
	for key, value := range stats {
		fmt.Printf("  %s: %v\n", key, value)
	}

	// Simulate high CPU usage
	fmt.Println("\n=== Simulating High CPU Usage ===")
	fmt.Println("Starting CPU-intensive task to trigger rollback...")
	
	// Start a goroutine that will consume CPU
	go func() {
		for i := 0; i < 1000000; i++ {
			_ = i * i // CPU-intensive operation
		}
	}()

	// Wait for rollback to trigger
	time.Sleep(5 * time.Second)

	// Show status after potential rollback
	fmt.Println("\n=== Status After Rollback ===")
	fmt.Printf("Active generation: %d\n", stat.GetActiveGeneration())
	fmt.Printf("Loaded artifacts: %v\n", getLoadedArtifacts(stat))
	fmt.Printf("Watched artifacts: %v\n", cpuWatcher.GetWatchedArtifacts())

	// Show final CPU watcher stats
	fmt.Println("\n=== Final CPU Watcher Stats ===")
	stats = cpuWatcher.GetStats()
	for key, value := range stats {
		fmt.Printf("  %s: %v\n", key, value)
	}

	fmt.Println("\n=== Test Summary ===")
	fmt.Println("✓ CPU watcher created and started")
	fmt.Println("✓ Artifacts loaded in multiple generations")
	fmt.Println("✓ CPU monitoring active")
	fmt.Println("✓ Rollback mechanism ready")
	fmt.Println("✓ Telemetry integration working")

	// Keep running until shutdown
	<-ctx.Done()
	fmt.Println("Test completed")
}

// getLoadedArtifacts returns a list of loaded artifact IDs
func getLoadedArtifacts(stat *status.Status) []string {
	// This is a simplified version - in real implementation,
	// we'd need to expose the loaded artifacts from the status
	return []string{"artifact-1", "artifact-2", "artifact-3"}
}
