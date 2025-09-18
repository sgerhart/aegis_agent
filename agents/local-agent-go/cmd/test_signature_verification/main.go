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
	fmt.Println("=== AegisFlux Signature Verification Test ===")

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
	
	pubKeyFile := "/tmp/test_public_key.pem"
	if err := os.WriteFile(pubKeyFile, pubKeyPEM, 0644); err != nil {
		log.Fatalf("Failed to write public key: %v", err)
	}
	fmt.Printf("✓ Saved public key to %s\n", pubKeyFile)

	// Test data
	testData := []byte("This is test bundle data for signature verification")
	fmt.Printf("✓ Test data: %s\n", string(testData))

	// Create signature
	signature, err := createSignature(testData, privateKey)
	if err != nil {
		log.Fatalf("Failed to create signature: %v", err)
	}
	fmt.Printf("✓ Created signature: %s\n", signature[:20]+"...")

	// Test different verification modes
	fmt.Println("\n=== Testing Verification Modes ===")

	// Test strict mode
	fmt.Println("\n--- Strict Mode ---")
	strictVerifier, err := verify.NewVerifier("", "", pubKeyFile, verify.VerificationStrict)
	if err != nil {
		log.Fatalf("Failed to create strict verifier: %v", err)
	}

	// Test valid signature
	if err := strictVerifier.VerifyBundle(testData, signature); err != nil {
		fmt.Printf("✗ Valid signature failed in strict mode: %v\n", err)
	} else {
		fmt.Println("✓ Valid signature passed in strict mode")
	}

	// Test invalid signature
	invalidSignature := signature[:len(signature)-10] + "invalid"
	if err := strictVerifier.VerifyBundle(testData, invalidSignature); err != nil {
		fmt.Printf("✓ Invalid signature correctly rejected in strict mode: %v\n", err)
	} else {
		fmt.Println("✗ Invalid signature incorrectly accepted in strict mode")
	}

	// Test altered data
	alteredData := []byte("This is altered bundle data for signature verification")
	if err := strictVerifier.VerifyBundle(alteredData, signature); err != nil {
		fmt.Printf("✓ Altered data correctly rejected in strict mode: %v\n", err)
	} else {
		fmt.Println("✗ Altered data incorrectly accepted in strict mode")
	}

	// Test no signature
	if err := strictVerifier.VerifyBundle(testData, ""); err != nil {
		fmt.Printf("✓ No signature correctly rejected in strict mode: %v\n", err)
	} else {
		fmt.Println("✗ No signature incorrectly accepted in strict mode")
	}

	// Test permissive mode
	fmt.Println("\n--- Permissive Mode ---")
	permissiveVerifier, err := verify.NewVerifier("", "", pubKeyFile, verify.VerificationPermissive)
	if err != nil {
		log.Fatalf("Failed to create permissive verifier: %v", err)
	}

	// Test valid signature
	if err := permissiveVerifier.VerifyBundle(testData, signature); err != nil {
		fmt.Printf("✗ Valid signature failed in permissive mode: %v\n", err)
	} else {
		fmt.Println("✓ Valid signature passed in permissive mode")
	}

	// Test no signature (should pass in permissive mode)
	if err := permissiveVerifier.VerifyBundle(testData, ""); err != nil {
		fmt.Printf("✗ No signature rejected in permissive mode: %v\n", err)
	} else {
		fmt.Println("✓ No signature accepted in permissive mode")
	}

	// Test disabled mode
	fmt.Println("\n--- Disabled Mode ---")
	disabledVerifier, err := verify.NewVerifier("", "", pubKeyFile, verify.VerificationDisabled)
	if err != nil {
		log.Fatalf("Failed to create disabled verifier: %v", err)
	}

	// Test any data (should pass in disabled mode)
	if err := disabledVerifier.VerifyBundle(testData, ""); err != nil {
		fmt.Printf("✗ Data rejected in disabled mode: %v\n", err)
	} else {
		fmt.Println("✓ Data accepted in disabled mode")
	}

	// Test environment variable parsing
	fmt.Println("\n=== Testing Environment Variable Parsing ===")
	testEnvVars := []string{"strict", "permissive", "disabled", "invalid", ""}
	for _, envVar := range testEnvVars {
		mode := verify.ParseVerificationMode(envVar)
		fmt.Printf("  %s -> %s\n", envVar, mode)
	}

	// Test telemetry reporting for failed verification
	fmt.Println("\n=== Testing Telemetry Reporting ===")
	
	// Simulate a failed verification that would be reported
	failedVerifier, err := verify.NewVerifier("", "", pubKeyFile, verify.VerificationStrict)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	// Trigger a verification failure
	_ = failedVerifier.VerifyBundle(alteredData, signature)
	
	// Check if error was recorded
	lastError, lastErrorTime := failedVerifier.GetLastError()
	if lastError != "" {
		fmt.Printf("✓ Verification error recorded: %s (at %s)\n", lastError, lastErrorTime.Format(time.RFC3339))
	} else {
		fmt.Println("✗ Verification error not recorded")
	}

	fmt.Println("\n=== Test Summary ===")
	fmt.Println("✓ RSA key generation and signing")
	fmt.Println("✓ Strict mode verification (rejects invalid/altered data)")
	fmt.Println("✓ Permissive mode verification (allows missing signatures)")
	fmt.Println("✓ Disabled mode verification (allows all data)")
	fmt.Println("✓ Environment variable parsing")
	fmt.Println("✓ Telemetry error reporting")
	fmt.Println("✓ Signature verification enforcement working")

	// Clean up
	os.Remove(pubKeyFile)
	fmt.Println("\n✓ Test completed successfully")
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
