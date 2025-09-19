package main

import (
	"log"
	"os"
	"agents/aegis/internal/identity"
)

func main() {
	actions := os.Getenv("ACTIONS_API_URL")
	if actions == "" { actions = "http://localhost:8083" }
	org := os.Getenv("ORG_ID"); if org == "" { org = "default" }

	// Set a local directory for testing
	os.Setenv("AEGIS_DATA_DIR", "./test-data")
	
	hostID := identity.ResolveHostID()
	pub, priv, err := identity.LoadOrCreateKeypair()
	if err != nil { log.Fatal(err) }

	agentUID, token, err := identity.Register(actions, org, hostID, pub, priv)
	if err != nil { log.Fatalf("register: %v", err) }
	log.Printf("registered ok: agent_uid=%s token=%s host_id=%s", agentUID, token, hostID)
}

