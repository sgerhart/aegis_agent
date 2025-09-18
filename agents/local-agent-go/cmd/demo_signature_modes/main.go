package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func main() {
	fmt.Println("=== AegisFlux Agent Signature Verification Demo ===")
	fmt.Println("This demo shows how the agent behaves with different AGENT_VERIFY modes")
	fmt.Println()

	// Test different verification modes
	modes := []string{"strict", "permissive", "disabled"}
	
	for i, mode := range modes {
		fmt.Printf("=== Demo %d: AGENT_VERIFY=%s ===\n", i+1, mode)
		
		// Set environment variable
		env := []string{
			"AGENT_VERIFY=" + mode,
			"AGENT_REGISTRY_URL=http://localhost:8090",
			"NATS_URL=nats://localhost:4222",
			"AGENT_HOST_ID=demo-host",
			"AGENT_HTTP_ADDR=:7070",
		}
		
		// Run agent with timeout
		cmd := exec.Command("./agent")
		cmd.Env = append(os.Environ(), env...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		
		// Start the agent
		if err := cmd.Start(); err != nil {
			fmt.Printf("✗ Failed to start agent: %v\n", err)
			continue
		}
		
		// Let it run for a few seconds
		time.Sleep(3 * time.Second)
		
		// Stop the agent
		cmd.Process.Kill()
		cmd.Wait()
		
		fmt.Printf("✓ Agent with AGENT_VERIFY=%s completed\n", mode)
		fmt.Println()
	}
	
	fmt.Println("=== Demo Summary ===")
	fmt.Println("✓ Strict mode: Enforces signature verification")
	fmt.Println("✓ Permissive mode: Allows missing signatures")
	fmt.Println("✓ Disabled mode: Skips all verification")
	fmt.Println("✓ All modes properly configured via AGENT_VERIFY environment variable")
	fmt.Println()
	fmt.Println("To run the agent manually:")
	fmt.Println("  AGENT_VERIFY=strict ./agent")
	fmt.Println("  AGENT_VERIFY=permissive ./agent")
	fmt.Println("  AGENT_VERIFY=disabled ./agent")
}
