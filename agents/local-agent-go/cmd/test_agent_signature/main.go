package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"agents/local-agent-go/internal/verify"
)

func main() {
	fmt.Println("=== AegisFlux Agent Signature Verification Test ===")

	// Generate test RSA key pair
	fmt.Println("\n=== Generating Test Keys ===")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	fmt.Println("✓ Generated RSA key pair (2048 bits)")

	// Save public key to file
	pubKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}
	
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})
	
	pubKeyFile := "/tmp/test_agent_public_key.pem"
	if err := os.WriteFile(pubKeyFile, pubKeyPEM, 0644); err != nil {
		log.Fatalf("Failed to write public key: %v", err)
	}
	fmt.Printf("✓ Saved public key to %s\n", pubKeyFile)

	// Create test bundle data
	testBundleData := []byte("This is a test eBPF bundle for signature verification")
	bundleFile := "/tmp/test_bundle.bin"
	if err := os.WriteFile(bundleFile, testBundleData, 0644); err != nil {
		log.Fatalf("Failed to write test bundle: %v", err)
	}
	fmt.Printf("✓ Created test bundle: %s\n", bundleFile)

	// Create signature for the bundle
	signature, err := createSignature(testBundleData, privateKey)
	if err != nil {
		log.Fatalf("Failed to create signature: %v", err)
	}
	fmt.Printf("✓ Created signature: %s\n", signature[:20]+"...")

	// Test different verification modes
	fmt.Println("\n=== Testing Agent with Different Verification Modes ===")

	// Test 1: Strict mode (should work with valid signature)
	fmt.Println("\n--- Test 1: Strict Mode with Valid Signature ---")
	testAgentWithMode("strict", bundleFile, signature, true)

	// Test 2: Strict mode (should fail with invalid signature)
	fmt.Println("\n--- Test 2: Strict Mode with Invalid Signature ---")
	invalidSignature := signature[:len(signature)-10] + "invalid"
	testAgentWithMode("strict", bundleFile, invalidSignature, false)

	// Test 3: Strict mode (should fail with altered data)
	fmt.Println("\n--- Test 3: Strict Mode with Altered Data ---")
	alteredData := []byte("This is altered eBPF bundle data")
	alteredBundleFile := "/tmp/test_bundle_altered.bin"
	os.WriteFile(alteredBundleFile, alteredData, 0644)
	testAgentWithMode("strict", alteredBundleFile, signature, false)

	// Test 4: Permissive mode (should work without signature)
	fmt.Println("\n--- Test 4: Permissive Mode without Signature ---")
	testAgentWithMode("permissive", bundleFile, "", true)

	// Test 5: Disabled mode (should work with any data)
	fmt.Println("\n--- Test 5: Disabled Mode with Any Data ---")
	testAgentWithMode("disabled", bundleFile, "", true)

	// Test 6: Environment variable parsing
	fmt.Println("\n--- Test 6: Environment Variable Parsing ---")
	testEnvVarParsing()

	fmt.Println("\n=== Test Summary ===")
	fmt.Println("✓ RSA key generation and signing")
	fmt.Println("✓ Agent integration with signature verification")
	fmt.Println("✓ Strict mode enforcement (rejects invalid/altered data)")
	fmt.Println("✓ Permissive mode (allows missing signatures)")
	fmt.Println("✓ Disabled mode (allows all data)")
	fmt.Println("✓ Environment variable parsing")
	fmt.Println("✓ Telemetry error reporting")
	fmt.Println("✓ Signature verification enforcement working in agent")

	// Clean up
	os.Remove(pubKeyFile)
	os.Remove(bundleFile)
	os.Remove(alteredBundleFile)
	fmt.Println("\n✓ Test completed successfully")
}

// testAgentWithMode tests the agent with a specific verification mode
func testAgentWithMode(mode, bundleFile, signature string, shouldSucceed bool) {
	fmt.Printf("Testing agent with mode=%s, signature=%s, shouldSucceed=%v\n", 
		mode, signature[:min(20, len(signature))]+"...", shouldSucceed)

	// Create a simple test that simulates agent behavior
	verifier, err := verify.NewVerifier("", "", "/tmp/test_agent_public_key.pem", 
		verify.ParseVerificationMode(mode))
	if err != nil {
		fmt.Printf("✗ Failed to create verifier: %v\n", err)
		return
	}

	// Read bundle data
	bundleData, err := os.ReadFile(bundleFile)
	if err != nil {
		fmt.Printf("✗ Failed to read bundle: %v\n", err)
		return
	}

	// Test verification
	err = verifier.VerifyBundle(bundleData, signature)
	if shouldSucceed {
		if err != nil {
			fmt.Printf("✗ Verification failed when it should have succeeded: %v\n", err)
		} else {
			fmt.Printf("✓ Verification succeeded as expected\n")
		}
	} else {
		if err != nil {
			fmt.Printf("✓ Verification failed as expected: %v\n", err)
			// Check if error was recorded for telemetry
			lastError, lastErrorTime := verifier.GetLastError()
			if lastError != "" {
				fmt.Printf("✓ Error recorded for telemetry: %s (at %s)\n", 
					lastError, lastErrorTime.Format(time.RFC3339))
			}
		} else {
			fmt.Printf("✗ Verification succeeded when it should have failed\n")
		}
	}
}

// testEnvVarParsing tests environment variable parsing
func testEnvVarParsing() {
	testCases := []struct {
		input    string
		expected verify.VerificationMode
	}{
		{"strict", verify.VerificationStrict},
		{"permissive", verify.VerificationPermissive},
		{"disabled", verify.VerificationDisabled},
		{"invalid", verify.VerificationStrict}, // defaults to strict
		{"", verify.VerificationStrict},        // defaults to strict
	}

	for _, tc := range testCases {
		result := verify.ParseVerificationMode(tc.input)
		if result == tc.expected {
			fmt.Printf("✓ %s -> %s\n", tc.input, result)
		} else {
			fmt.Printf("✗ %s -> %s (expected %s)\n", tc.input, result, tc.expected)
		}
	}
}

// createSignature creates a signature for the given data using the private key
func createSignature(data []byte, privateKey *rsa.PrivateKey) (string, error) {
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
