package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"agents/aegis/internal/identity"
)

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getLocalIP() string {
	// Try to get the primary network interface IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()
	
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func main() {
	// Get configuration from environment
	regURL := getenv("AGENT_REGISTRY_URL", "http://localhost:8090")
	natsURL := getenv("NATS_URL", "nats://localhost:4222")
	actionsURL := getenv("ACTIONS_API_URL", "http://localhost:8083")
	orgID := getenv("ORG_ID", "default")
	httpAddr := getenv("AGENT_HTTP_ADDR", ":7070")

	// Resolve host ID using the new identity system
	hostID := identity.ResolveHostID()
	localIP := getLocalIP()
	log.Printf("[agent] resolved host_id: %s", hostID)
	log.Printf("[agent] local IP address: %s", localIP)

	// Load or create identity keypair
	pub, priv, err := identity.LoadOrCreateKeypair()
	if err != nil {
		log.Fatalf("Failed to load/create identity keypair: %v", err)
	}
	log.Printf("[agent] loaded identity keypair, public key: %s", identity.PubKeyB64(pub))

	// Register with the actions API
	agentUID, bootstrapToken, err := identity.Register(actionsURL, orgID, hostID, pub, priv)
	if err != nil {
		log.Printf("[agent] registration failed: %v", err)
		log.Printf("[agent] continuing without registration...")
	} else {
		log.Printf("[agent] registered successfully: agent_uid=%s", agentUID)
		log.Printf("[agent] bootstrap_token=%s", bootstrapToken)
	}

	// Initialize HTTP server for status
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		statusData := map[string]any{
			"host_id":        hostID,
			"agent_uid":      agentUID,
			"registered":     err == nil,
			"org_id":         orgID,
			"local_ip":       localIP,
			"actions_url":    actionsURL,
			"registry_url":   regURL,
			"nats_url":       natsURL,
			"public_key":     identity.PubKeyB64(pub),
			"uptime_seconds": time.Since(time.Now()).Seconds(),
		}
		json.NewEncoder(w).Encode(statusData)
	})

	srv := &http.Server{Addr: httpAddr, Handler: mux}
	go func() {
		log.Printf("[agent] status server listening on %s", httpAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	// Set up signal handling
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	log.Printf("[agent] starting; host_id=%s org_id=%s actions_url=%s registry=%s nats=%s", 
		hostID, orgID, actionsURL, regURL, natsURL)

	// Main loop - simplified for demo
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[agent] shutting down")
			_ = srv.Shutdown(context.Background())
			return
		case <-ticker.C:
			log.Printf("[agent] heartbeat - host_id=%s agent_uid=%s", hostID, agentUID)
		}
	}
}
