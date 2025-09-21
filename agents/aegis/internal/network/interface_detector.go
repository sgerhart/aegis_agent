package network

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// InterfaceInfo represents information about a network interface
type InterfaceInfo struct {
	Name         string   `json:"name"`
	Index        int      `json:"index"`
	MAC          string   `json:"mac"`
	Addresses    []string `json:"addresses"`
	IsUp         bool     `json:"is_up"`
	IsLoopback   bool     `json:"is_loopback"`
	IsBackend    bool     `json:"is_backend"`    // Can reach backend
	IsDefault    bool     `json:"is_default"`    // Default interface for backend
	BackendReachable bool `json:"backend_reachable"`
}

// InterfaceDetector handles automatic interface detection
type InterfaceDetector struct {
	backendURL string
}

// NewInterfaceDetector creates a new interface detector
func NewInterfaceDetector(backendURL string) *InterfaceDetector {
	return &InterfaceDetector{
		backendURL: backendURL,
	}
}

// DetectInterfaces discovers all network interfaces and their capabilities
func (id *InterfaceDetector) DetectInterfaces() ([]InterfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	var results []InterfaceInfo
	for _, iface := range interfaces {
		info := InterfaceInfo{
			Name:       iface.Name,
			Index:      iface.Index,
			MAC:        iface.HardwareAddr.String(),
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
		}

		// Get addresses for this interface
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				info.Addresses = append(info.Addresses, addr.String())
			}
		}

		// Test backend connectivity if interface is up and not loopback
		if info.IsUp && !info.IsLoopback {
			info.BackendReachable = id.testBackendConnectivity(iface.Name)
		}

		results = append(results, info)
	}

	// Sort by backend reachability and interface name
	sort.Slice(results, func(i, j int) bool {
		if results[i].BackendReachable != results[j].BackendReachable {
			return results[i].BackendReachable
		}
		return results[i].Name < results[j].Name
	})

	return results, nil
}

// GetDefaultInterface returns the interface used for backend connectivity
func (id *InterfaceDetector) GetDefaultInterface() (*InterfaceInfo, error) {
	interfaces, err := id.DetectInterfaces()
	if err != nil {
		return nil, err
	}

	// Find the first interface that can reach the backend
	for _, iface := range interfaces {
		if iface.BackendReachable {
			iface.IsDefault = true
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("no interface can reach backend at %s", id.backendURL)
}

// GetBackendInterfaces returns all interfaces that can reach the backend
func (id *InterfaceDetector) GetBackendInterfaces() ([]InterfaceInfo, error) {
	interfaces, err := id.DetectInterfaces()
	if err != nil {
		return nil, err
	}

	var backendInterfaces []InterfaceInfo
	for _, iface := range interfaces {
		if iface.BackendReachable {
			iface.IsBackend = true
			backendInterfaces = append(backendInterfaces, iface)
		}
	}

	return backendInterfaces, nil
}

// GetEnforcementInterfaces returns interfaces suitable for policy enforcement
func (id *InterfaceDetector) GetEnforcementInterfaces() ([]InterfaceInfo, error) {
	interfaces, err := id.DetectInterfaces()
	if err != nil {
		return nil, err
	}

	var enforcementInterfaces []InterfaceInfo
	for _, iface := range interfaces {
		// Include interfaces that are up and not loopback
		if iface.IsUp && !iface.IsLoopback {
			enforcementInterfaces = append(enforcementInterfaces, iface)
		}
	}

	return enforcementInterfaces, nil
}

// testBackendConnectivity tests if an interface can reach the backend
func (id *InterfaceDetector) testBackendConnectivity(ifaceName string) bool {
	// Parse backend URL to get host
	host := id.backendURL
	if strings.HasPrefix(host, "http://") {
		host = host[7:]
	} else if strings.HasPrefix(host, "https://") {
		host = host[8:]
	}
	if strings.HasPrefix(host, "nats://") {
		host = host[7:]
	}

	// Remove port if present
	if colon := strings.LastIndex(host, ":"); colon != -1 {
		host = host[:colon]
	}

	// Test connectivity using the interface
	conn, err := net.Dial("udp", host+":80")
	if err != nil {
		return false
	}
	defer conn.Close()

	// Check if the connection uses the specified interface
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if localAddr.IP == nil {
		return false
	}

	// Get the interface for this local address
	iface, err := InterfaceByIP(localAddr.IP)
	if err != nil {
		return false
	}

	return iface.Name == ifaceName
}

// InterfaceByIP finds an interface by IP address
func InterfaceByIP(ip net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.Equal(ip) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for IP %s", ip)
}

