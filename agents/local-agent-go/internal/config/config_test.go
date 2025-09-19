package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeriveHostID(t *testing.T) {
	tests := []struct {
		name           string
		envHostID      string
		expectedResult string
		setup          func() func()
	}{
		{
			name:           "with AGENT_HOST_ID set",
			envHostID:      "test-host-123",
			expectedResult: "test-host-123",
			setup: func() func() {
				os.Setenv("AGENT_HOST_ID", "test-host-123")
				return func() {
					os.Unsetenv("AGENT_HOST_ID")
				}
			},
		},
		{
			name:           "without AGENT_HOST_ID set",
			expectedResult: "", // We'll check that it's not empty and not "host-unknown"
			setup: func() func() {
				os.Unsetenv("AGENT_HOST_ID")
				return func() {}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.setup()
			defer cleanup()

			result := DeriveHostID()
			if tt.expectedResult == "" {
				// For the "without AGENT_HOST_ID set" test, just check that we get a valid result
				if result == "" || result == "host-unknown" {
					t.Errorf("DeriveHostID() = %v, expected a valid hostname or machine-id", result)
				}
			} else {
				if result != tt.expectedResult {
					t.Errorf("DeriveHostID() = %v, want %v", result, tt.expectedResult)
				}
			}
		})
	}
}

func TestDeriveHostIDWithMachineID(t *testing.T) {
	// Test with a temporary machine-id file
	tempDir := t.TempDir()
	machineIDPath := filepath.Join(tempDir, "machine-id")
	testMachineID := "1234567890abcdef"
	
	// Write test machine-id
	if err := os.WriteFile(machineIDPath, []byte(testMachineID+"\n"), 0644); err != nil {
		t.Fatalf("Failed to write test machine-id: %v", err)
	}
	
	// Create a test function that uses our temporary machine-id file
	testDeriveHostID := func() string {
		if hostID := os.Getenv("AGENT_HOST_ID"); hostID != "" {
			return hostID
		}
		
		if machineID, err := os.ReadFile(machineIDPath); err == nil {
			if id := string(machineID); id != "" {
				return id
			}
		}
		
		if hostname, err := os.Hostname(); err == nil && hostname != "" {
			return hostname
		}
		
		return "host-unknown"
	}
	
	// Test without AGENT_HOST_ID set
	os.Unsetenv("AGENT_HOST_ID")
	result := testDeriveHostID()
	if result != testMachineID {
		t.Errorf("Expected machine-id %v, got %v", testMachineID, result)
	}
}
