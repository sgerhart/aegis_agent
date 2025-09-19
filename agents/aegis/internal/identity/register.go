package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type initReq struct {
	OrgID          string         `json:"org_id"`
	HostID         string         `json:"host_id"`
	AgentPubKey    string         `json:"agent_pubkey"`
	MachineIDHash  string         `json:"machine_id_hash,omitempty"`
	AgentVersion   string         `json:"agent_version,omitempty"`
	Capabilities   map[string]any `json:"capabilities,omitempty"`
	Platform       map[string]any `json:"platform,omitempty"`
	Network        map[string]any `json:"network,omitempty"`
}
type initResp struct {
	RegistrationID string `json:"registration_id"`
	Nonce          string `json:"nonce"`
	ServerTime     string `json:"server_time"`
}
type completeReq struct {
	RegistrationID string `json:"registration_id"`
	HostID         string `json:"host_id"`
	Signature      string `json:"signature"`
}
type completeResp struct {
	AgentUID       string `json:"agent_uid"`
	BootstrapToken string `json:"bootstrap_token"`
}

func Register(actionsURL, orgID, hostID string, pub, priv []byte) (string, string, error) {
	// Gather enhanced metadata
	machineIDHash := getMachineIDHash()
	agentVersion := getAgentVersion()
	capabilities := getCapabilities()
	platform := getPlatformInfo()
	network := getNetworkInfo()

	// INIT
	req := initReq{
		OrgID:          orgID,
		HostID:         hostID,
		AgentPubKey:    base64.StdEncoding.EncodeToString(pub),
		MachineIDHash:  machineIDHash,
		AgentVersion:   agentVersion,
		Capabilities:   capabilities,
		Platform:       platform,
		Network:        network,
	}
	
	b, _ := json.Marshal(req)
	resp, err := http.Post(actionsURL+"/agents/register/init", "application/json", bytes.NewReader(b))
	if err != nil { return "", "", err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { body,_ := io.ReadAll(resp.Body); return "", "", fmt.Errorf("init %s", string(body)) }
	var ir initResp; json.NewDecoder(resp.Body).Decode(&ir)

	// COMPLETE
	msg := append(decodeB64(ir.Nonce), []byte(ir.ServerTime+hostID)...)
	sig, _ := Sign(priv, msg)
	b2, _ := json.Marshal(completeReq{ RegistrationID: ir.RegistrationID, HostID: hostID, Signature: sig })
	resp2, err := http.Post(actionsURL+"/agents/register/complete", "application/json", bytes.NewReader(b2))
	if err != nil { return "", "", err }
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 { body,_ := io.ReadAll(resp2.Body); return "", "", fmt.Errorf("complete %s", string(body)) }
	var cr completeResp; json.NewDecoder(resp2.Body).Decode(&cr)
	_ = os.WriteFile("/var/lib/aegis/agent_uid", []byte(cr.AgentUID), 0o600)
	return cr.AgentUID, cr.BootstrapToken, nil
}
func decodeB64(s string) []byte { b,_ := base64.StdEncoding.DecodeString(s); return b }

// getMachineIDHash returns a hash of the machine ID
func getMachineIDHash() string {
	// Try to read /etc/machine-id first
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		machineID := strings.TrimSpace(string(data))
		if machineID != "" {
			hash := sha256.Sum256([]byte(machineID))
			return fmt.Sprintf("sha256:%x", hash)
		}
	}
	
	// Fallback to hostname
	if hostname, err := os.Hostname(); err == nil {
		hash := sha256.Sum256([]byte(hostname))
		return fmt.Sprintf("sha256:%x", hash)
	}
	
	return "unknown"
}

// getAgentVersion returns the agent version
func getAgentVersion() string {
	// Try to get version from environment or return default
	if version := os.Getenv("AGENT_VERSION"); version != "" {
		return version
	}
	return "1.0.0"
}

// getCapabilities returns detected system capabilities
func getCapabilities() map[string]any {
	capabilities := map[string]any{
		"ebpf": false,
		"tc": false,
		"cgroup": false,
		"bpf": false,
	}
	
	// Check for eBPF support
	if _, err := os.Stat("/sys/fs/bpf"); err == nil {
		capabilities["ebpf"] = true
		capabilities["bpf"] = true
	}
	
	// Check for TC support
	if _, err := exec.LookPath("tc"); err == nil {
		capabilities["tc"] = true
	}
	
	// Check for cgroup support
	if _, err := os.Stat("/sys/fs/cgroup"); err == nil {
		capabilities["cgroup"] = true
	}
	
	return capabilities
}

// getPlatformInfo returns platform information
func getPlatformInfo() map[string]any {
	platform := map[string]any{
		"os": runtime.GOOS,
		"arch": runtime.GOARCH,
	}
	
	// Get hostname
	if hostname, err := os.Hostname(); err == nil {
		platform["hostname"] = hostname
	}
	
	// Get kernel version on Linux
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/version"); err == nil {
			version := strings.TrimSpace(string(data))
			platform["kernel_version"] = version
		}
	}
	
	return platform
}

// getNetworkInfo returns network interface information
func getNetworkInfo() map[string]any {
	network := map[string]any{
		"ifaces": map[string]any{},
	}
	
	// Get network interfaces
	if interfaces, err := net.Interfaces(); err == nil {
		ifaces := map[string]any{}
		var allAddrs []string
		
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 {
				continue // Skip down interfaces
			}
			
			ifaceInfo := map[string]any{
				"mac": iface.HardwareAddr.String(),
			}
			
			// Get addresses for this interface
			if addrs, err := iface.Addrs(); err == nil {
				var addrStrings []string
				for _, addr := range addrs {
					addrStrings = append(addrStrings, addr.String())
				}
				ifaceInfo["addrs"] = addrStrings
				allAddrs = append(allAddrs, addrStrings...)
			}
			
			ifaces[iface.Name] = ifaceInfo
		}
		
		network["ifaces"] = ifaces
		network["addrs"] = allAddrs
	}
	
	return network
}

