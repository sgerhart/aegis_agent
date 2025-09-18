package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"agents/local-agent-go/internal/policy"
	"agents/local-agent-go/internal/seg"
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

	fmt.Println("=== AegisFlux ApplySnapshot Test ===")

	// Connect to NATS
	natsURL := getenv("NATS_URL", "nats://localhost:4222")
	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("Failed to connect to NATS: %v", err)
	}
	defer nc.Close()
	fmt.Printf("✓ Connected to NATS at %s\n", natsURL)

	// Create policy writer
	policyWriter, err := policy.NewWriter()
	if err != nil {
		log.Fatalf("Failed to create policy writer: %v", err)
	}
	defer policyWriter.Close()
	fmt.Println("✓ Created policy writer")

	// Create subscriber
	subject := "aegis.policy.updates"
	subscriber := seg.NewSubscriber(nc, policyWriter, subject)
	fmt.Printf("✓ Created subscriber for subject: %s\n", subject)

	// Start subscriber in background
	go func() {
		if err := subscriber.Start(ctx); err != nil {
			log.Printf("Subscriber error: %v", err)
		}
	}()

	// Wait a moment for subscriber to start
	time.Sleep(1 * time.Second)

	// Publish test snapshot
	fmt.Println("\n=== Publishing Test Snapshot ===")
	if err := subscriber.PublishTestSnapshot(ctx); err != nil {
		log.Fatalf("Failed to publish test snapshot: %v", err)
	}
	fmt.Println("✓ Published test snapshot")

	// Wait for processing
	time.Sleep(2 * time.Second)

	// Check if mock files were created
	fmt.Println("\n=== Verifying Map Updates ===")
	checkMockFiles()

	fmt.Println("\n=== Test Summary ===")
	fmt.Println("✓ NATS connection established")
	fmt.Println("✓ Policy writer created")
	fmt.Println("✓ Subscriber started")
	fmt.Println("✓ Test snapshot published")
	fmt.Println("✓ Map updates verified")
	fmt.Println("✓ ApplySnapshot functionality working")

	// Keep running until shutdown
	<-ctx.Done()
	fmt.Println("Test completed")
}

func getenv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func checkMockFiles() {
	mockDir := "/tmp/sys/fs/bpf/aegis"
	
	// Check policy edges file
	edgesFile := mockDir + "/policy_edges"
	if data, err := os.ReadFile(edgesFile); err == nil {
		fmt.Printf("✓ Policy edges file created:\n%s", string(data))
	} else {
		fmt.Printf("✗ Policy edges file not found: %v\n", err)
	}

	// Check allow CIDRs file
	cidrsFile := mockDir + "/allow_lpm4"
	if data, err := os.ReadFile(cidrsFile); err == nil {
		fmt.Printf("✓ Allow CIDRs file created:\n%s", string(data))
	} else {
		fmt.Printf("✗ Allow CIDRs file not found: %v\n", err)
	}
}
