package network

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
)

// InterfaceManager manages eBPF program attachment to network interfaces
type InterfaceManager struct {
	detector        *InterfaceDetector
	attachedInterfaces map[string]*InterfaceInfo
	links           map[string]interface{} // Store eBPF links for cleanup
	mu              sync.RWMutex
}

// NewInterfaceManager creates a new interface manager
func NewInterfaceManager(backendURL string) *InterfaceManager {
	return &InterfaceManager{
		detector:           NewInterfaceDetector(backendURL),
		attachedInterfaces: make(map[string]*InterfaceInfo),
		links:              make(map[string]interface{}),
	}
}

// GetDefaultInterface returns the interface used for backend connectivity
func (im *InterfaceManager) GetDefaultInterface() (*InterfaceInfo, error) {
	return im.detector.GetDefaultInterface()
}

// GetBackendInterfaces returns all interfaces that can reach the backend
func (im *InterfaceManager) GetBackendInterfaces() ([]InterfaceInfo, error) {
	return im.detector.GetBackendInterfaces()
}

// GetEnforcementInterfaces returns interfaces suitable for policy enforcement
func (im *InterfaceManager) GetEnforcementInterfaces() ([]InterfaceInfo, error) {
	return im.detector.GetEnforcementInterfaces()
}

// AttachToDefaultInterface attaches eBPF programs to the default backend interface
func (im *InterfaceManager) AttachToDefaultInterface() error {
	defaultIface, err := im.GetDefaultInterface()
	if err != nil {
		return fmt.Errorf("failed to get default interface: %w", err)
	}

	log.Printf("[interface] Using default interface: %s (index %d)", defaultIface.Name, defaultIface.Index)
	return im.AttachToInterface(defaultIface.Name)
}

// AttachToInterface attaches eBPF programs to a specific interface
func (im *InterfaceManager) AttachToInterface(ifaceName string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	// Check if already attached
	if _, exists := im.attachedInterfaces[ifaceName]; exists {
		log.Printf("[interface] Already attached to interface %s", ifaceName)
		return nil
	}

	// Get interface info
	interfaces, err := im.detector.DetectInterfaces()
	if err != nil {
		return fmt.Errorf("failed to detect interfaces: %w", err)
	}

	var targetInterface *InterfaceInfo
	for _, iface := range interfaces {
		if iface.Name == ifaceName {
			targetInterface = &iface
			break
		}
	}

	if targetInterface == nil {
		return fmt.Errorf("interface %s not found", ifaceName)
	}

	if !targetInterface.IsUp {
		return fmt.Errorf("interface %s is down", ifaceName)
	}

	// Attach eBPF programs
	if err := im.attachEBPFPrograms(ifaceName); err != nil {
		return fmt.Errorf("failed to attach eBPF programs to %s: %w", ifaceName, err)
	}

	// Store interface info
	im.attachedInterfaces[ifaceName] = targetInterface
	log.Printf("[interface] Successfully attached to interface %s", ifaceName)

	return nil
}

// AttachToInterfaces attaches eBPF programs to multiple interfaces
func (im *InterfaceManager) AttachToInterfaces(ifaceNames []string) error {
	var errors []string
	successCount := 0

	for _, ifaceName := range ifaceNames {
		if err := im.AttachToInterface(ifaceName); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", ifaceName, err))
			log.Printf("[interface] Failed to attach to interface %s: %v", ifaceName, err)
		} else {
			successCount++
		}
	}

	log.Printf("[interface] Successfully attached to %d/%d interfaces", successCount, len(ifaceNames))

	if len(errors) > 0 {
		return fmt.Errorf("some attachments failed: %s", strings.Join(errors, "; "))
	}

	return nil
}

// DetachFromInterface detaches eBPF programs from an interface
func (im *InterfaceManager) DetachFromInterface(ifaceName string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	if _, exists := im.attachedInterfaces[ifaceName]; !exists {
		log.Printf("[interface] Interface %s not attached", ifaceName)
		return nil
	}

	// Detach eBPF programs
	if err := im.detachEBPFPrograms(ifaceName); err != nil {
		log.Printf("[interface] Warning: failed to detach eBPF programs from %s: %v", ifaceName, err)
	}

	// Remove from tracking
	delete(im.attachedInterfaces, ifaceName)
	delete(im.links, ifaceName)

	log.Printf("[interface] Detached from interface %s", ifaceName)
	return nil
}

// ReattachToInterface detaches and reattaches eBPF programs to an interface
func (im *InterfaceManager) ReattachToInterface(ifaceName string) error {
	if err := im.DetachFromInterface(ifaceName); err != nil {
		return fmt.Errorf("failed to detach from %s: %w", ifaceName, err)
	}

	return im.AttachToInterface(ifaceName)
}

// GetAttachedInterfaces returns currently attached interfaces
func (im *InterfaceManager) GetAttachedInterfaces() map[string]*InterfaceInfo {
	im.mu.RLock()
	defer im.mu.RUnlock()

	result := make(map[string]*InterfaceInfo)
	for name, info := range im.attachedInterfaces {
		result[name] = info
	}
	return result
}

// IsAttached checks if an interface is currently attached
func (im *InterfaceManager) IsAttached(ifaceName string) bool {
	im.mu.RLock()
	defer im.mu.RUnlock()

	_, exists := im.attachedInterfaces[ifaceName]
	return exists
}

// Close detaches from all interfaces and cleans up
func (im *InterfaceManager) Close() error {
	im.mu.Lock()
	defer im.mu.Unlock()

	var errors []string
	for ifaceName := range im.attachedInterfaces {
		if err := im.detachEBPFPrograms(ifaceName); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", ifaceName, err))
		}
	}

	im.attachedInterfaces = make(map[string]*InterfaceInfo)
	im.links = make(map[string]interface{})

	if len(errors) > 0 {
		return fmt.Errorf("some detachments failed: %s", strings.Join(errors, "; "))
	}

	return nil
}

// attachEBPFPrograms attaches eBPF programs to an interface
func (im *InterfaceManager) attachEBPFPrograms(ifaceName string) error {
	// Ensure clsact qdisc exists
	if err := im.ensureClsactQdisc(ifaceName); err != nil {
		return fmt.Errorf("failed to ensure clsact qdisc: %w", err)
	}

	// Attach TC ingress classifier
	if err := im.attachTCClassifier(ifaceName); err != nil {
		return fmt.Errorf("failed to attach TC classifier: %w", err)
	}

	// Attach cgroup program (only once)
	if !im.isCgroupAttached() {
		if err := im.attachCgroupProgram(); err != nil {
			return fmt.Errorf("failed to attach cgroup program: %w", err)
		}
	}

	return nil
}

// detachEBPFPrograms detaches eBPF programs from an interface
func (im *InterfaceManager) detachEBPFPrograms(ifaceName string) error {
	// Remove TC filter
	if err := im.removeTCFilter(ifaceName); err != nil {
		log.Printf("[interface] Warning: failed to remove TC filter from %s: %v", ifaceName, err)
	}

	return nil
}

// ensureClsactQdisc ensures a clsact qdisc exists on the interface
func (im *InterfaceManager) ensureClsactQdisc(ifaceName string) error {
	// Check if clsact qdisc already exists
	cmd := exec.Command("tc", "qdisc", "show", "dev", ifaceName)
	output, err := cmd.Output()
	if err == nil && strings.Contains(string(output), "clsact") {
		log.Printf("[interface] clsact qdisc already exists on %s", ifaceName)
		return nil
	}

	// Add clsact qdisc
	cmd = exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add clsact qdisc: %w", err)
	}

	log.Printf("[interface] Added clsact qdisc to %s", ifaceName)
	return nil
}

// attachTCClassifier attaches the TC classifier program
func (im *InterfaceManager) attachTCClassifier(ifaceName string) error {
	// Use the working eBPF program
	cmd := exec.Command("tc", "filter", "add", "dev", ifaceName, "ingress", 
		"bpf", "obj", "bpf/bpf/seg_ingress_tc.o", "sec", "classifier", "direct-action")
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to attach TC classifier: %w", err)
	}

	log.Printf("[interface] Attached TC classifier to %s", ifaceName)
	return nil
}

// attachCgroupProgram attaches the cgroup program
func (im *InterfaceManager) attachCgroupProgram() error {
	// Use the working eBPF program
	cmd := exec.Command("bpftool", "cgroup", "attach", "/sys/fs/cgroup", 
		"bpf/bpf/seg_egress_cgroup.o", "cgroup/connect4")
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to attach cgroup program: %w", err)
	}

	log.Printf("[interface] Attached cgroup program")
	return nil
}

// removeTCFilter removes the TC filter from an interface
func (im *InterfaceManager) removeTCFilter(ifaceName string) error {
	cmd := exec.Command("tc", "filter", "del", "dev", ifaceName, "ingress")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove TC filter: %w", err)
	}

	log.Printf("[interface] Removed TC filter from %s", ifaceName)
	return nil
}

// isCgroupAttached checks if cgroup program is already attached
func (im *InterfaceManager) isCgroupAttached() bool {
	// Simple check - in production, you'd want to verify the actual attachment
	return false // For now, always try to attach
}

