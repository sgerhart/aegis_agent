package polling

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/nats-io/nats.go"
	"agents/aegis/internal/policy"
	"agents/aegis/internal/rollout"
	"agents/aegis/internal/telemetry"
)

// TelemetryEmitter interface for telemetry backends
type TelemetryEmitter interface {
	EmitBackendComm(endpoint, method, action string, statusCode int, duration time.Duration, dataSize int64, errorMsg string)
}

// PollingClient handles backend communication for AegisFlux
type PollingClient struct {
	hostID       string
	agentUID     string
	registryURL  string
	actionsURL   string
	natsURL      string
	pollInterval time.Duration
	telemetry    TelemetryEmitter
	natsConn     *nats.Conn
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	httpClient   *http.Client
	validator    *policy.PolicyValidator
	rollbackMgr  *rollout.RollbackManager
	historyMgr   *policy.PolicyHistoryManager
	auditLogger  *telemetry.AuditLogger
}

// RegistrationRequest represents Phase 1 registration
type RegistrationRequest struct {
	OrgID         string                 `json:"org_id"`
	HostID        string                 `json:"host_id"`
	AgentPubkey   string                 `json:"agent_pubkey"`
	MachineIDHash string                 `json:"machine_id_hash"`
	AgentVersion  string                 `json:"agent_version"`
	Capabilities  map[string]interface{} `json:"capabilities"`
	Platform      map[string]interface{} `json:"platform"`
	Network       map[string]interface{} `json:"network"`
}

// RegistrationInitResponse represents Phase 1 response
type RegistrationInitResponse struct {
	RegistrationID string `json:"registration_id"`
	Nonce          string `json:"nonce"`
	ServerTime     string `json:"server_time"`
}

// RegistrationCompleteRequest represents Phase 2 registration
type RegistrationCompleteRequest struct {
	RegistrationID string `json:"registration_id"`
	HostID         string `json:"host_id"`
	Signature      string `json:"signature"`
}

// RegistrationCompleteResponse represents Phase 2 response
type RegistrationCompleteResponse struct {
	AgentUID       string `json:"agent_uid"`
	BootstrapToken string `json:"bootstrap_token"`
}

// Artifact represents an eBPF program artifact
type Artifact struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	Type         string                 `json:"type"`
	Architecture string                 `json:"architecture"`
	KernelVersion string                `json:"kernel_version"`
	CreatedAt    string                 `json:"created_at"`
	Size         int64                  `json:"size"`
	Checksum     string                 `json:"checksum"`
	Signature    string                 `json:"signature"`
	Metadata     map[string]interface{} `json:"metadata"`
	Tags         []string               `json:"tags"`
}

// ArtifactResponse represents the artifacts response
type ArtifactResponse struct {
	Artifacts []Artifact `json:"artifacts"`
	Total     int        `json:"total"`
}

// NewPollingClient creates a new polling client
func NewPollingClient(hostID, registryURL, actionsURL, natsURL string, telemetry TelemetryEmitter) *PollingClient {
	// Generate Ed25519 keypair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Printf("[polling] Failed to generate keypair: %v", err)
		return nil
	}

	pollInterval := 30 * time.Second
	if interval := os.Getenv("AGENT_POLL_INTERVAL_SEC"); interval != "" {
		if d, err := time.ParseDuration(interval + "s"); err == nil {
			pollInterval = d
		}
	}

	// Initialize rollback and history managers
	rollbackMgr := rollout.NewRollbackManager("/var/lib/aegis/rollback_history.json", 100)
	historyMgr := policy.NewPolicyHistoryManager("/var/lib/aegis/policy_history.json", 500)
	auditLogger := telemetry.NewAuditLogger("/var/lib/aegis/audit_log.json", 1000)

	return &PollingClient{
		hostID:       hostID,
		registryURL:  registryURL,
		actionsURL:   actionsURL,
		natsURL:      natsURL,
		pollInterval: pollInterval,
		telemetry:    telemetry,
		privateKey:   privateKey,
		publicKey:    publicKey,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		validator:    policy.NewPolicyValidator(),
		rollbackMgr:  rollbackMgr,
		historyMgr:   historyMgr,
		auditLogger:  auditLogger,
	}
}

// Register performs the two-phase registration with Actions API
func (pc *PollingClient) Register() error {
	log.Printf("[polling] Starting agent registration with %s", pc.actionsURL)

	// Phase 1: Registration Init
	regReq := RegistrationRequest{
		OrgID:         getEnvOrDefault("AGENT_ORG_ID", "security-team"),
		HostID:        pc.hostID,
		AgentPubkey:   base64.StdEncoding.EncodeToString(pc.publicKey),
		MachineIDHash: pc.getMachineIDHash(),
		AgentVersion:  "1.0.0",
		Capabilities:  pc.getCapabilities(),
		Platform:      pc.getPlatformInfo(),
		Network:       pc.getNetworkInfo(),
	}

	regData, err := json.Marshal(regReq)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %v", err)
	}

	resp, err := pc.httpClient.Post(pc.actionsURL+"/agents/register/init", "application/json", bytes.NewBuffer(regData))
	if err != nil {
		return fmt.Errorf("registration init failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration init failed with status %d: %s", resp.StatusCode, string(body))
	}

	var initResp RegistrationInitResponse
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return fmt.Errorf("failed to decode init response: %v", err)
	}

	log.Printf("[polling] Registration init successful, registration_id: %s", initResp.RegistrationID)

	// Phase 2: Complete registration with signature
	nonce, err := base64.StdEncoding.DecodeString(initResp.Nonce)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %v", err)
	}

	// Create signature over (nonce || server_time || host_id)
	sigData := append(nonce, []byte(initResp.ServerTime)...)
	sigData = append(sigData, []byte(pc.hostID)...)
	signature := ed25519.Sign(pc.privateKey, sigData)

	completeReq := RegistrationCompleteRequest{
		RegistrationID: initResp.RegistrationID,
		HostID:         pc.hostID,
		Signature:      base64.StdEncoding.EncodeToString(signature),
	}

	completeData, err := json.Marshal(completeReq)
	if err != nil {
		return fmt.Errorf("failed to marshal complete request: %v", err)
	}

	resp2, err := pc.httpClient.Post(pc.actionsURL+"/agents/register/complete", "application/json", bytes.NewBuffer(completeData))
	if err != nil {
		return fmt.Errorf("registration complete failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		return fmt.Errorf("registration complete failed with status %d: %s", resp2.StatusCode, string(body))
	}

	var completeResp RegistrationCompleteResponse
	if err := json.NewDecoder(resp2.Body).Decode(&completeResp); err != nil {
		return fmt.Errorf("failed to decode complete response: %v", err)
	}

	pc.agentUID = completeResp.AgentUID
	log.Printf("[polling] Registration complete! Agent UID: %s", pc.agentUID)

	// Emit telemetry
	pc.telemetry.EmitBackendComm(pc.actionsURL+"/agents/register", "POST", "registration_complete", 200, 0, 0, "")

	return nil
}

// ConnectNATS establishes NATS connection for telemetry
func (pc *PollingClient) ConnectNATS() error {
	log.Printf("[polling] Connecting to NATS at %s", pc.natsURL)

	nc, err := nats.Connect(pc.natsURL)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %v", err)
	}

	pc.natsConn = nc
	log.Printf("[polling] NATS connection established")

	// Send initial heartbeat
	pc.sendHeartbeat()

	return nil
}

// StartPolling begins the artifact polling loop
func (pc *PollingClient) StartPolling() {
	log.Printf("[polling] Starting polling loop, interval: %v", pc.pollInterval)

	ticker := time.NewTicker(pc.pollInterval)
	defer ticker.Stop()

	// Poll immediately on start
	pc.pollForArtifacts()

	for range ticker.C {
		pc.pollForArtifacts()
	}
}

// pollForArtifacts polls the BPF Registry for assigned artifacts
func (pc *PollingClient) pollForArtifacts() {
	start := time.Now()
	url := fmt.Sprintf("%s/artifacts/for-host/%s", pc.registryURL, pc.hostID)

	log.Printf("[polling] Polling for artifacts: %s", url)

	resp, err := pc.httpClient.Get(url)
	if err != nil {
		log.Printf("[polling] Poll failed: %v", err)
		pc.telemetry.EmitBackendComm(url, "GET", "poll_failed", 0, time.Since(start), 0, err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[polling] Poll failed with status %d: %s", resp.StatusCode, string(body))
		pc.telemetry.EmitBackendComm(url, "GET", "poll_failed", resp.StatusCode, time.Since(start), 0, string(body))
		return
	}

	var artifactResp ArtifactResponse
	if err := json.NewDecoder(resp.Body).Decode(&artifactResp); err != nil {
		log.Printf("[polling] Failed to decode artifacts response: %v", err)
		pc.telemetry.EmitBackendComm(url, "GET", "decode_failed", resp.StatusCode, time.Since(start), 0, err.Error())
		return
	}

	log.Printf("[polling] Found %d artifacts assigned to host", len(artifactResp.Artifacts))

	// Process each artifact
	for _, artifact := range artifactResp.Artifacts {
		pc.processArtifact(artifact)
	}

	// Emit successful poll telemetry
	pc.telemetry.EmitBackendComm(url, "GET", "poll_success", resp.StatusCode, time.Since(start), int64(len(artifactResp.Artifacts)), "")
}

// processArtifact handles downloading and loading an artifact
func (pc *PollingClient) processArtifact(artifact Artifact) {
	log.Printf("[polling] Processing artifact: %s (%s)", artifact.Name, artifact.ID)

	// Download artifact binary
	binaryURL := fmt.Sprintf("%s/artifacts/%s/binary", pc.registryURL, artifact.ID)
	resp, err := pc.httpClient.Get(binaryURL)
	if err != nil {
		log.Printf("[polling] Failed to download artifact %s: %v", artifact.ID, err)
		pc.sendArtifactTelemetry(artifact.ID, "download_failed", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[polling] Download failed with status %d: %s", resp.StatusCode, string(body))
		pc.sendArtifactTelemetry(artifact.ID, "download_failed", string(body))
		return
	}

	// Read artifact binary
	binaryData, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[polling] Failed to read artifact binary: %v", err)
		pc.sendArtifactTelemetry(artifact.ID, "read_failed", err.Error())
		return
	}

	log.Printf("[polling] Downloaded artifact %s (%d bytes)", artifact.ID, len(binaryData))

	// Verify checksum
	if !pc.verifyChecksum(binaryData, artifact.Checksum) {
		log.Printf("[polling] Checksum verification failed for artifact %s", artifact.ID)
		pc.sendArtifactTelemetry(artifact.ID, "checksum_failed", "checksum mismatch")
		return
	}

	// Extract and load eBPF program
	if err := pc.loadEBPFProgram(artifact, binaryData); err != nil {
		log.Printf("[polling] Failed to load eBPF program for artifact %s: %v", artifact.ID, err)
		pc.sendArtifactTelemetry(artifact.ID, "load_failed", err.Error())
		return
	}

	log.Printf("[polling] Artifact %s processed and loaded successfully", artifact.ID)
	pc.sendArtifactTelemetry(artifact.ID, "program_loaded", "success")
}

// verifyChecksum verifies the SHA256 checksum of downloaded data
func (pc *PollingClient) verifyChecksum(data []byte, expectedChecksum string) bool {
	hash := sha256.Sum256(data)
	actualHash := fmt.Sprintf("%x", hash)
	
	// Handle both formats: "sha256-{hash}" and just "{hash}"
	var expectedHash string
	if strings.HasPrefix(expectedChecksum, "sha256-") {
		expectedHash = strings.TrimPrefix(expectedChecksum, "sha256-")
	} else {
		expectedHash = expectedChecksum
	}
	
	return actualHash == expectedHash
}

// sendArtifactTelemetry sends artifact-related telemetry via NATS
func (pc *PollingClient) sendArtifactTelemetry(artifactID, eventType, details string) {
	if pc.natsConn == nil {
		return
	}

	event := map[string]interface{}{
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"host_id":     pc.hostID,
		"agent_uid":   pc.agentUID,
		"event_type":  eventType,
		"artifact_id": artifactID,
		"details":     details,
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[polling] Failed to marshal telemetry: %v", err)
		return
	}

	subject := fmt.Sprintf("aegis.telemetry.host.%s", pc.hostID)
	if err := pc.natsConn.Publish(subject, data); err != nil {
		log.Printf("[polling] Failed to send telemetry: %v", err)
	}
}

// loadEBPFProgram extracts tar.zst artifact and applies policy to existing eBPF maps
func (pc *PollingClient) loadEBPFProgram(artifact Artifact, binaryData []byte) error {
	log.Printf("[polling] Processing eBPF policy from artifact %s", artifact.ID)
	
	// Create temporary directory for extraction
	tempDir := fmt.Sprintf("/tmp/aegis_artifact_%s", artifact.ID)
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Write binary data to temp file
	artifactFile := filepath.Join(tempDir, "artifact.tar.zst")
	if err := os.WriteFile(artifactFile, binaryData, 0644); err != nil {
		return fmt.Errorf("failed to write artifact file: %v", err)
	}
	
	// Extract tar.zst file
	extractedDir := filepath.Join(tempDir, "extracted")
	if err := os.MkdirAll(extractedDir, 0755); err != nil {
		return fmt.Errorf("failed to create extraction directory: %v", err)
	}
	
	// Extract using zstd and tar (two-step process)
	// Step 1: Decompress zstd to tar
	zstdCmd := exec.Command("zstd", "-d", artifactFile, "-o", filepath.Join(tempDir, "artifact.tar"))
	log.Printf("[polling] Running zstd command: %v", zstdCmd.Args)
	if err := zstdCmd.Run(); err != nil {
		log.Printf("[polling] zstd command failed: %v", err)
		return fmt.Errorf("failed to decompress tar.zst: %v", err)
	}
	log.Printf("[polling] zstd decompression successful")
	
	// Step 2: Extract tar file (ignore ownership issues with --no-same-owner)
	tarCmd := exec.Command("tar", "-xf", filepath.Join(tempDir, "artifact.tar"), "--no-same-owner", "-C", tempDir)
	log.Printf("[polling] Running tar command: %v", tarCmd.Args)
	
	// Capture command output for debugging
	output, err := tarCmd.CombinedOutput()
	if err != nil {
		log.Printf("[polling] tar command failed: %v", err)
		log.Printf("[polling] tar command output: %s", string(output))
		return fmt.Errorf("failed to extract tar: %v", err)
	}
	log.Printf("[polling] tar extraction successful")
	log.Printf("[polling] tar command output: %s", string(output))
	
	// Parse policy metadata - try different possible filenames
	var metadataFile, configFile string
	
	// List all files in temp directory for debugging
	if files, err := os.ReadDir(tempDir); err == nil {
		log.Printf("[polling] Files in temp directory: %v", func() []string {
			var fileNames []string
			for _, file := range files {
				fileNames = append(fileNames, file.Name())
			}
			return fileNames
		}())
	}
	
	// Try to find metadata file with common patterns
	possibleMetadataFiles := []string{
		filepath.Join(tempDir, "temp_metadata.json"),
		filepath.Join(tempDir, "icmp_metadata.json"),
		filepath.Join(tempDir, "metadata.json"),
	}
	
	for _, file := range possibleMetadataFiles {
		if _, err := os.Stat(file); err == nil {
			metadataFile = file
			log.Printf("[polling] Found metadata file: %s", file)
			break
		}
	}
	
	// Try to find config file with common patterns
	possibleConfigFiles := []string{
		filepath.Join(tempDir, "temp_config.json"),
		filepath.Join(tempDir, "icmp_config.json"),
		filepath.Join(tempDir, "config.json"),
	}
	
	for _, file := range possibleConfigFiles {
		if _, err := os.Stat(file); err == nil {
			configFile = file
			log.Printf("[polling] Found config file: %s", file)
			break
		}
	}
	
	var policy PolicyRule
	var config ConfigRule
	
	// Parse metadata.json
	if metadataData, err := os.ReadFile(metadataFile); err == nil {
		if err := json.Unmarshal(metadataData, &policy); err != nil {
			log.Printf("[polling] Warning: Failed to parse metadata.json: %v", err)
		}
	}
	
	// Parse config.json
	if configData, err := os.ReadFile(configFile); err == nil {
		if err := json.Unmarshal(configData, &config); err != nil {
			log.Printf("[polling] Warning: Failed to parse config.json: %v", err)
		}
	}
	
	// Apply policy to existing eBPF maps
	if err := pc.applyPolicyToEBPFMaps(policy, config); err != nil {
		return fmt.Errorf("failed to apply policy to eBPF maps: %v", err)
	}
	
	log.Printf("[polling] Successfully applied policy from artifact %s", artifact.ID)
	return nil
}

// PolicyRule represents the policy from artifact metadata
type PolicyRule struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Type        string `json:"type"`
	PolicyType  string `json:"policy_type"`
	TargetIP    string `json:"target_ip"`
	Protocol    string `json:"protocol"`
	Direction   string `json:"direction"`
	Hook        string `json:"hook"`
	Action      string `json:"action"`
}

// ConfigRule represents the configuration from artifact config
type ConfigRule struct {
	TargetIP  string `json:"target_ip"`
	Protocol  string `json:"protocol"`
	Direction string `json:"direction"`
	Interface string `json:"interface"`
	Priority  int    `json:"priority"`
	TTL       int    `json:"ttl"`
}

// applyPolicyToEBPFMaps applies the policy rule to existing eBPF maps
func (pc *PollingClient) applyPolicyToEBPFMaps(policy PolicyRule, config ConfigRule) error {
	log.Printf("[polling] Applying policy: %s -> %s (%s %s)", policy.TargetIP, policy.Action, policy.Protocol, policy.Direction)
	
	// Create snapshot before applying policy
	mapState := pc.getCurrentMapState()
	policyData := map[string]interface{}{
		"name":     policy.Name,
		"target_ip": policy.TargetIP,
		"action":   policy.Action,
		"protocol": policy.Protocol,
		"direction": policy.Direction,
	}
	
	snapshot := pc.rollbackMgr.CreateSnapshot(
		policy.Name,
		policy.Name,
		policyData,
		mapState,
		fmt.Sprintf("Applying policy: %s -> %s", policy.TargetIP, policy.Action),
	)
	
	// Validate policy before application
	if err := pc.validatePolicyBeforeApplication(policy); err != nil {
		// Record failure in history
		pc.historyMgr.RecordPolicyChange("apply", policy.Name, policy.Name, "network", "Policy validation failed", "system", "artifact", policyData, false, err)
		
		// Create failure snapshot
		pc.rollbackMgr.CreateFailureSnapshot(policy.Name, policy.Name, policyData, mapState, fmt.Sprintf("Validation failed: %v", err))
		
		// Log validation failure
		pc.auditLogger.LogValidationFailure(policy.Name, policy.Name, err.Error(), policyData)
		
		return fmt.Errorf("policy validation failed: %w", err)
	}
	
	// Convert IP address to network byte order
	ip := net.ParseIP(policy.TargetIP)
	if ip == nil {
		err := fmt.Errorf("invalid IP address: %s", policy.TargetIP)
		pc.historyMgr.RecordPolicyChange("apply", policy.Name, policy.Name, "network", "Invalid IP address", "system", "artifact", policyData, false, err)
		pc.rollbackMgr.CreateFailureSnapshot(policy.Name, policy.Name, policyData, mapState, err.Error())
		return err
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		err := fmt.Errorf("not an IPv4 address: %s", policy.TargetIP)
		pc.historyMgr.RecordPolicyChange("apply", policy.Name, policy.Name, "network", "Not an IPv4 address", "system", "artifact", policyData, false, err)
		pc.rollbackMgr.CreateFailureSnapshot(policy.Name, policy.Name, policyData, mapState, err.Error())
		return err
	}
	
	// Note: For aegis_blocked_d map, we don't need protocol filtering
	// The eBPF program handles protocol checking internally
	
	// Convert action string to number
	var action uint8
	switch strings.ToLower(policy.Action) {
	case "drop", "block", "deny":
		action = 1 // BLOCK (value 1 in aegis_blocked_d means block)
	case "allow", "pass":
		action = 0 // ALLOW (value 0 in aegis_blocked_d means allow)
	default:
		return fmt.Errorf("unsupported action: %s", policy.Action)
	}
	
	log.Printf("[polling] Converting action '%s' to value %d", policy.Action, action)
	
	// Update the aegis_blocked_d map using native eBPF library (most secure approach)
	log.Printf("[polling] Updating eBPF map using native Go eBPF library")
	
	// Load the existing pinned map using native eBPF library
	blockedMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis_blocked_destinations", nil)
	if err != nil {
		log.Printf("[polling] Failed to load pinned map, trying alternative path: %v", err)
		// Try alternative path
		blockedMap, err = ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/aegis_blocked_d", nil)
		if err != nil {
			return fmt.Errorf("failed to load eBPF map: %v", err)
		}
	}
	defer blockedMap.Close()
	
	// Convert IP address to network byte order for the key
	ipBytes := make([]byte, 4)
	copy(ipBytes, ipv4)
	
	// Update the map using native eBPF library
	if err := blockedMap.Put(ipBytes, []byte{action}); err != nil {
		// Record failure in history
		pc.historyMgr.RecordPolicyChange("apply", policy.Name, policy.Name, "network", "Failed to update eBPF map", "system", "artifact", policyData, false, err)
		
		// Create failure snapshot
		pc.rollbackMgr.CreateFailureSnapshot(policy.Name, policy.Name, policyData, mapState, fmt.Sprintf("Map update failed: %v", err))
		
		return fmt.Errorf("failed to update eBPF map: %v", err)
	}
	
	// Record successful application in history
	pc.historyMgr.RecordPolicyChange("apply", policy.Name, policy.Name, "network", "Policy applied successfully", "system", "artifact", policyData, true, nil)
	
	// Log successful policy application
	pc.auditLogger.LogPolicyChange("apply", policy.Name, policy.Name, "system", "artifact", policyData)
	
	// Log map update
	pc.auditLogger.LogMapUpdate("aegis_blocked_destinations", "put", "system", map[string]interface{}{
		"target_ip": policy.TargetIP,
		"action":    policy.Action,
		"protocol":  policy.Protocol,
	})
	
	log.Printf("[polling] Successfully updated eBPF map with rule: %s -> %s (native library)", policy.TargetIP, policy.Action)
	return nil
}

// sendHeartbeat sends periodic heartbeat via NATS
func (pc *PollingClient) sendHeartbeat() {
	if pc.natsConn == nil {
		return
	}

	event := map[string]interface{}{
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
		"host_id":        pc.hostID,
		"agent_uid":      pc.agentUID,
		"event_type":     "heartbeat",
		"uptime_seconds": time.Since(time.Now().Add(-time.Hour)).Seconds(), // Placeholder
		"memory_mb":      45,   // Placeholder
		"cpu_percent":    2.1,  // Placeholder
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[polling] Failed to marshal heartbeat: %v", err)
		return
	}

	subject := fmt.Sprintf("aegis.telemetry.host.%s", pc.hostID)
	if err := pc.natsConn.Publish(subject, data); err != nil {
		log.Printf("[polling] Failed to send heartbeat: %v", err)
	}
}

// Helper functions
func (pc *PollingClient) getMachineIDHash() string {
	// Simplified machine ID hash
	hash := sha256.Sum256([]byte(pc.hostID + "machine-id"))
	return fmt.Sprintf("%x", hash)
}

func (pc *PollingClient) getCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"ebpf_loading":   true,
		"ebpf_attach":    true,
		"map_operations": true,
		"kernel_modules": []string{"bpf", "netfilter"},
		"supported_hooks": []string{"xdp", "tc", "tracepoint", "kprobe"},
		"max_programs":   10,
		"max_maps":       50,
	}
}

func (pc *PollingClient) getPlatformInfo() map[string]interface{} {
	return map[string]interface{}{
		"hostname":       pc.hostID,
		"os":             "linux",
		"kernel_version": "5.15.0-91-generic", // Would get from uname
		"architecture":   "arm64",
	}
}

func (pc *PollingClient) getNetworkInfo() map[string]interface{} {
	return map[string]interface{}{
		"addrs": []string{"192.168.193.129/24"},
		"ifaces": map[string]interface{}{
			"ens160": map[string]interface{}{
				"addrs": []string{"192.168.193.129/24"},
				"mac":   "00:50:56:a1:b2:c3", // Placeholder
			},
		},
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// validatePolicyBeforeApplication validates a policy before applying it to eBPF maps
func (pc *PollingClient) validatePolicyBeforeApplication(policy PolicyRule) error {
	// Check rate limiting
	if !pc.validator.RateLimiter().Allow() {
		return fmt.Errorf("rate limit exceeded: too many policy updates")
	}
	
	// Validate the policy rule
	result := pc.validator.ValidatePolicyRule(&policy)
	if !result.Valid {
		return fmt.Errorf("policy validation failed: %s", strings.Join(result.Errors, "; "))
	}
	
	// Log warnings if any
	if len(result.Warnings) > 0 {
		log.Printf("[polling] Policy validation warnings: %s", strings.Join(result.Warnings, "; "))
	}
	
	// Log successful validation
	log.Printf("[polling] Policy validation successful for rule: %s", policy.Name)
	return nil
}

// getCurrentMapState captures the current state of eBPF maps for rollback
func (pc *PollingClient) getCurrentMapState() map[string]interface{} {
	// This is a simplified implementation
	// In a full implementation, you would:
	// 1. Load all relevant eBPF maps
	// 2. Read their current contents
	// 3. Serialize the state for rollback
	
	mapState := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"maps": map[string]interface{}{
			"aegis_blocked_destinations": "current_state",
			"policy_edges":               "current_state",
			"allow_lpm4":                 "current_state",
			"mode":                       "current_state",
		},
	}
	
	log.Printf("[polling] Captured current map state for rollback")
	return mapState
}
