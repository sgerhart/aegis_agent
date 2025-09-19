package config

import (
	"os"
	"strings"
)

// DeriveHostID determines the host ID using the following priority:
// 1. AGENT_HOST_ID environment variable (if set)
// 2. /etc/machine-id (if present and not empty)
// 3. os.Hostname() (if successful)
// 4. "host-unknown" (fallback)
func DeriveHostID() string {
	// 1. Check environment variable first
	if hostID := os.Getenv("AGENT_HOST_ID"); hostID != "" {
		return hostID
	}

	// 2. Try to read /etc/machine-id
	if machineID, err := os.ReadFile("/etc/machine-id"); err == nil {
		if id := strings.TrimSpace(string(machineID)); id != "" {
			return id
		}
	}

	// 3. Fall back to hostname
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return hostname
	}

	// 4. Final fallback
	return "host-unknown"
}

