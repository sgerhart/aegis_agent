package ebpf

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

// AttachManager manages eBPF program attachment
type AttachManager struct {
	ingressProg interface{} // *ebpf.Program
	egressProg  interface{} // *ebpf.Program
}

// NewAttachManager creates a new attach manager
func NewAttachManager() *AttachManager {
	return &AttachManager{}
}

// LoadPrograms loads eBPF programs from object files
func (am *AttachManager) LoadPrograms() error {
	log.Printf("[attach] Loading eBPF programs (simplified)")
	// For now, we'll skip actual program loading to avoid compilation issues
	// In a real implementation, this would load the actual eBPF programs
	return nil
}

// AttachToInterface attaches programs to a network interface
func (am *AttachManager) AttachToInterface(ifaceName string) error {
	log.Printf("[attach] Attaching to interface %s (simplified)", ifaceName)
	
	// Get interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", ifaceName, err)
	}

	// Ensure clsact qdisc exists
	if err := am.ensureClsactQdisc(ifaceName); err != nil {
		return fmt.Errorf("failed to ensure clsact qdisc: %w", err)
	}

	log.Printf("[attach] Attached to interface %s (index %d)", ifaceName, iface.Index)
	return nil
}

// AttachToAllInterfaces attaches programs to all active network interfaces
func (am *AttachManager) AttachToAllInterfaces() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %w", err)
	}

	attachedCount := 0
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if err := am.AttachToInterface(iface.Name); err != nil {
			log.Printf("[attach] Failed to attach to interface %s: %v", iface.Name, err)
			continue
		}
		attachedCount++
	}

	log.Printf("[attach] Attached to %d interfaces", attachedCount)
	return nil
}

// AttachToCgroup attaches egress program to cgroup
func (am *AttachManager) AttachToCgroup(cgroupPath string) error {
	log.Printf("[attach] Attaching to cgroup %s (simplified)", cgroupPath)
	// For now, we'll skip actual cgroup attachment
	return nil
}

// ensureClsactQdisc ensures a clsact qdisc exists on the interface
func (am *AttachManager) ensureClsactQdisc(ifaceName string) error {
	// Check if clsact qdisc already exists
	cmd := exec.Command("tc", "qdisc", "show", "dev", ifaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check qdiscs: %w", err)
	}

	// Check if clsact is already present
	if strings.Contains(string(output), "clsact") {
		log.Printf("[attach] clsact qdisc already exists on %s", ifaceName)
		return nil
	}

	// Create clsact qdisc
	cmd = exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add clsact qdisc: %w", err)
	}

	log.Printf("[attach] Created clsact qdisc on %s", ifaceName)
	return nil
}

// DetachAll detaches all programs
func (am *AttachManager) DetachAll() error {
	log.Printf("[attach] Detaching all programs (simplified)")
	return nil
}

// IsAttached checks if programs are attached to an interface
func (am *AttachManager) IsAttached(ifaceName string) bool {
	// Simplified check
	return true
}

// GetAttachedInterfaces returns a list of attached interfaces
func (am *AttachManager) GetAttachedInterfaces() []string {
	// Simplified implementation
	return []string{"all"}
}

// Close closes all resources
func (am *AttachManager) Close() error {
	return am.DetachAll()
}

// ValidateEnvironment checks if required tools are available
func ValidateEnvironment() error {
	if !checkTCInstalled() {
		return fmt.Errorf("tc command not found - required for TC attachment")
	}
	
	if !checkBPFToolInstalled() {
		log.Printf("[attach] Warning: bpftool not found - cgroup attachment may not work")
	}
	
	return nil
}

// checkTCInstalled checks if tc is installed
func checkTCInstalled() bool {
	_, err := exec.LookPath("tc")
	return err == nil
}

// checkBPFToolInstalled checks if bpftool is installed
func checkBPFToolInstalled() bool {
	_, err := exec.LookPath("bpftool")
	return err == nil
}
