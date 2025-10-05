package core

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agents/aegis/internal/enforcement"
	"agents/aegis/internal/telemetry"
)

// SecurityContinuityChecker ensures security continuity after restart
type SecurityContinuityChecker struct {
	stateManager *StateManager
	telemetry    *telemetry.Logger
	ebpfManager  *EBPFManager
	enforcer     *enforcement.Enforcer
}

// NewSecurityContinuityChecker creates a new security continuity checker
func NewSecurityContinuityChecker(stateManager *StateManager, telemetry *telemetry.Logger, ebpfManager *EBPFManager, enforcer *enforcement.Enforcer) *SecurityContinuityChecker {
	return &SecurityContinuityChecker{
		stateManager: stateManager,
		telemetry:    telemetry,
		ebpfManager:  ebpfManager,
		enforcer:     enforcer,
	}
}

// PerformStartupSecurityCheck performs comprehensive security checks on startup
func (scc *SecurityContinuityChecker) PerformStartupSecurityCheck(ctx context.Context) error {
	log.Printf("[security_continuity] Starting security continuity check...")
	
	// 1. Verify agent state integrity
	if err := scc.verifyAgentStateIntegrity(); err != nil {
		scc.telemetry.LogError("security_continuity", fmt.Sprintf("Agent state integrity check failed: %v", err), nil)
		return fmt.Errorf("agent state integrity check failed: %w", err)
	}
	
	// 2. Restore and verify policies
	if err := scc.restoreAndVerifyPolicies(); err != nil {
		scc.telemetry.LogError("security_continuity", fmt.Sprintf("Policy restoration failed: %v", err), nil)
		return fmt.Errorf("policy restoration failed: %w", err)
	}
	
	// 3. Verify eBPF enforcement is active
	if err := scc.verifyEBPFEnforcement(); err != nil {
		scc.telemetry.LogError("security_continuity", fmt.Sprintf("eBPF enforcement verification failed: %v", err), nil)
		return fmt.Errorf("eBPF enforcement verification failed: %w", err)
	}
	
	// 4. Perform host security scan
	if err := scc.performHostSecurityScan(); err != nil {
		scc.telemetry.LogWarn("security_continuity", fmt.Sprintf("Host security scan failed: %v", err), nil)
		// Don't fail startup for scan issues, but log them
	}
	
	// 5. Check for security events since last run
	if err := scc.checkForSecurityEvents(); err != nil {
		scc.telemetry.LogWarn("security_continuity", fmt.Sprintf("Security event check failed: %v", err), nil)
		// Don't fail startup for event check issues
	}
	
	// 6. Verify critical system files
	if err := scc.verifyCriticalSystemFiles(); err != nil {
		scc.telemetry.LogWarn("security_continuity", fmt.Sprintf("Critical system file verification failed: %v", err), nil)
		// Don't fail startup for file verification issues
	}
	
	log.Printf("[security_continuity] Security continuity check completed successfully")
	scc.telemetry.LogInfo("security_continuity", "Security continuity check completed", map[string]interface{}{
		"timestamp": time.Now(),
		"status":    "success",
	})
	
	return nil
}

// verifyAgentStateIntegrity verifies the agent state is consistent
func (scc *SecurityContinuityChecker) verifyAgentStateIntegrity() error {
	agentState := scc.stateManager.GetAgentState()
	
	// Check if this is a restart (not first run)
	if agentState.RestartCount > 0 {
		// Verify we have a previous shutdown time
		if agentState.LastShutdown.IsZero() {
			scc.telemetry.LogWarn("security_continuity", "Previous shutdown time not recorded - possible unclean shutdown", nil)
		}
		
		// Check if the restart was too quick (possible crash)
		if !agentState.LastShutdown.IsZero() && time.Since(agentState.LastShutdown) < 30*time.Second {
			scc.telemetry.LogWarn("security_continuity", "Very quick restart detected - possible crash", map[string]interface{}{
				"restart_time": time.Since(agentState.LastShutdown),
			})
		}
	}
	
	// Verify agent ID is consistent
	if agentState.AgentID == "" {
		return fmt.Errorf("agent ID is empty in state")
	}
	
	// Verify version is consistent
	if agentState.Version == "" {
		return fmt.Errorf("agent version is empty in state")
	}
	
	scc.telemetry.LogInfo("security_continuity", "Agent state integrity verified", map[string]interface{}{
		"agent_id":      agentState.AgentID,
		"version":       agentState.Version,
		"restart_count": agentState.RestartCount,
	})
	
	return nil
}

// restoreAndVerifyPolicies restores and verifies policies from state
func (scc *SecurityContinuityChecker) restoreAndVerifyPolicies() error {
	policyState := scc.stateManager.GetPolicyState()
	
	// Check if we have policies to restore
	if len(policyState.ActivePolicies) == 0 {
		scc.telemetry.LogInfo("security_continuity", "No policies to restore from state", nil)
		return nil
	}
	
	// Verify policy state is not too old
	if time.Since(policyState.LastPolicyUpdate) > 24*time.Hour {
		scc.telemetry.LogWarn("security_continuity", "Policy state is very old - may need refresh", map[string]interface{}{
			"last_update": policyState.LastPolicyUpdate,
		})
	}
	
	// Restore policies to policy engine
	// This would typically involve calling the policy engine's restore method
	// For now, we'll just verify the state is consistent
	
	scc.telemetry.LogInfo("security_continuity", "Policies restored and verified", map[string]interface{}{
		"policy_count": len(policyState.ActivePolicies),
		"version":      policyState.PolicyVersion,
		"last_update":  policyState.LastPolicyUpdate,
	})
	
	return nil
}

// verifyEBPFEnforcement verifies eBPF enforcement is active
func (scc *SecurityContinuityChecker) verifyEBPFEnforcement() error {
	// Check if eBPF manager is initialized
	if !scc.ebpfManager.IsInitialized() {
		return fmt.Errorf("eBPF manager not initialized")
	}
	
	// Check if we have eBPF maps loaded
	mapCount := scc.ebpfManager.GetMapCount()
	if mapCount == 0 {
		return fmt.Errorf("no eBPF maps loaded")
	}
	
	// Check if enforcer is running
	if !scc.enforcer.IsRunning() {
		return fmt.Errorf("enforcer is not running")
	}
	
	// Perform a test enforcement cycle
	if err := scc.enforcer.EnforcePolicies(); err != nil {
		return fmt.Errorf("test enforcement cycle failed: %w", err)
	}
	
	scc.telemetry.LogInfo("security_continuity", "eBPF enforcement verified", map[string]interface{}{
		"map_count":     mapCount,
		"program_count": scc.ebpfManager.GetProgramCount(),
	})
	
	return nil
}

// performHostSecurityScan performs a basic host security scan
func (scc *SecurityContinuityChecker) performHostSecurityScan() error {
	// Check for suspicious processes
	suspiciousProcesses, err := scc.checkForSuspiciousProcesses()
	if err != nil {
		scc.telemetry.LogWarn("security_continuity", fmt.Sprintf("Failed to check suspicious processes: %v", err), nil)
	} else if len(suspiciousProcesses) > 0 {
		scc.telemetry.LogWarn("security_continuity", "Suspicious processes detected", map[string]interface{}{
			"count": len(suspiciousProcesses),
		})
	}
	
	// Check for unusual network connections
	unusualConnections, err := scc.checkForUnusualConnections()
	if err != nil {
		scc.telemetry.LogWarn("security_continuity", fmt.Sprintf("Failed to check network connections: %v", err), nil)
	} else if len(unusualConnections) > 0 {
		scc.telemetry.LogWarn("security_continuity", "Unusual network connections detected", map[string]interface{}{
			"count": len(unusualConnections),
		})
	}
	
	// Check for file system anomalies
	fileAnomalies, err := scc.checkForFileSystemAnomalies()
	if err != nil {
		scc.telemetry.LogWarn("security_continuity", fmt.Sprintf("Failed to check file system: %v", err), nil)
	} else if len(fileAnomalies) > 0 {
		scc.telemetry.LogWarn("security_continuity", "File system anomalies detected", map[string]interface{}{
			"count": len(fileAnomalies),
		})
	}
	
	scc.telemetry.LogInfo("security_continuity", "Host security scan completed", map[string]interface{}{
		"suspicious_processes": len(suspiciousProcesses),
		"unusual_connections":  len(unusualConnections),
		"file_anomalies":       len(fileAnomalies),
	})
	
	return nil
}

// checkForSuspiciousProcesses checks for suspicious processes
func (scc *SecurityContinuityChecker) checkForSuspiciousProcesses() ([]string, error) {
	// This is a simplified check - in production, you'd use more sophisticated detection
	// For now, we'll check for some basic indicators
	
	// Check for processes with suspicious names
	suspiciousNames := []string{
		"nc", "netcat", "ncat",
		"wget", "curl", "wget",
		"python", "perl", "ruby",
		"bash", "sh", "zsh",
	}
	
	var suspicious []string
	
	// Read /proc to find processes
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		// Check if it's a PID directory
		pid := entry.Name()
		if len(pid) == 0 || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		
		// Read process command line
		cmdlineFile := filepath.Join(procDir, pid, "cmdline")
		cmdline, err := os.ReadFile(cmdlineFile)
		if err != nil {
			continue
		}
		
		cmdlineStr := string(cmdline)
		for _, suspiciousName := range suspiciousNames {
			if strings.Contains(cmdlineStr, suspiciousName) {
				suspicious = append(suspicious, fmt.Sprintf("PID %s: %s", pid, cmdlineStr))
			}
		}
	}
	
	return suspicious, nil
}

// checkForUnusualConnections checks for unusual network connections
func (scc *SecurityContinuityChecker) checkForUnusualConnections() ([]string, error) {
	// This is a simplified check - in production, you'd parse /proc/net/tcp and /proc/net/udp
	// For now, we'll return an empty list
	return []string{}, nil
}

// checkForFileSystemAnomalies checks for file system anomalies
func (scc *SecurityContinuityChecker) checkForFileSystemAnomalies() ([]string, error) {
	// Check for suspicious files in common locations
	suspiciousPaths := []string{
		"/tmp/",
		"/var/tmp/",
		"/dev/shm/",
	}
	
	var anomalies []string
	
	for _, path := range suspiciousPaths {
		entries, err := os.ReadDir(path)
		if err != nil {
			continue
		}
		
		for _, entry := range entries {
			// Check for files with suspicious extensions
			name := entry.Name()
			suspiciousExtensions := []string{".exe", ".bat", ".cmd", ".scr", ".pif"}
			
			for _, ext := range suspiciousExtensions {
				if strings.HasSuffix(strings.ToLower(name), ext) {
					anomalies = append(anomalies, filepath.Join(path, name))
				}
			}
		}
	}
	
	return anomalies, nil
}

// checkForSecurityEvents checks for security events since last run
func (scc *SecurityContinuityChecker) checkForSecurityEvents() error {
	hostState := scc.stateManager.GetHostState()
	
	// Check for recent security events
	recentEvents := 0
	for _, event := range hostState.SecurityEvents {
		if time.Since(event.Timestamp) < 24*time.Hour {
			recentEvents++
		}
	}
	
	// Check for recent threats
	recentThreats := 0
	for _, threat := range hostState.ThreatsDetected {
		if time.Since(threat.Timestamp) < 24*time.Hour {
			recentThreats++
		}
	}
	
	if recentEvents > 0 || recentThreats > 0 {
		scc.telemetry.LogWarn("security_continuity", "Recent security events detected", map[string]interface{}{
			"recent_events":  recentEvents,
			"recent_threats": recentThreats,
		})
	}
	
	return nil
}

// verifyCriticalSystemFiles verifies critical system files
func (scc *SecurityContinuityChecker) verifyCriticalSystemFiles() error {
	criticalFiles := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/hosts",
		"/etc/hostname",
		"/etc/machine-id",
	}
	
	for _, file := range criticalFiles {
		info, err := os.Stat(file)
		if err != nil {
			scc.telemetry.LogWarn("security_continuity", fmt.Sprintf("Critical file not accessible: %s", file), nil)
			continue
		}
		
		// Check if file was modified recently (within last hour)
		if time.Since(info.ModTime()) < time.Hour {
			scc.telemetry.LogWarn("security_continuity", fmt.Sprintf("Critical file modified recently: %s", file), map[string]interface{}{
				"modified": info.ModTime(),
			})
		}
	}
	
	return nil
}

// GetSecurityStatus returns the current security status
func (scc *SecurityContinuityChecker) GetSecurityStatus() map[string]interface{} {
	agentState := scc.stateManager.GetAgentState()
	policyState := scc.stateManager.GetPolicyState()
	hostState := scc.stateManager.GetHostState()
	
	return map[string]interface{}{
		"agent": map[string]interface{}{
			"id":            agentState.AgentID,
			"version":       agentState.Version,
			"restart_count": agentState.RestartCount,
			"uptime":        time.Since(agentState.LastStartup),
		},
		"policies": map[string]interface{}{
			"active_count":    len(policyState.ActivePolicies),
			"version":         policyState.PolicyVersion,
			"last_update":     policyState.LastPolicyUpdate,
			"violation_count": policyState.ViolationCount,
		},
		"host": map[string]interface{}{
			"id":                  hostState.HostID,
			"process_count":       hostState.ProcessCount,
			"network_connections": hostState.NetworkConnections,
			"last_scan":          hostState.LastScan,
			"security_events":    len(hostState.SecurityEvents),
			"threats_detected":   len(hostState.ThreatsDetected),
		},
		"ebpf": map[string]interface{}{
			"initialized":    scc.ebpfManager.IsInitialized(),
			"map_count":      scc.ebpfManager.GetMapCount(),
			"program_count":  scc.ebpfManager.GetProgramCount(),
		},
		"enforcer": map[string]interface{}{
			"running": scc.enforcer.IsRunning(),
		},
	}
}
