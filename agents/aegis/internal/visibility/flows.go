package visibility

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// FlowInfo represents a network flow
type FlowInfo struct {
	PID       uint32    `json:"pid"`
	LAddr     string    `json:"laddr"`     // Local address:port
	RAddr     string    `json:"raddr"`     // Remote address:port
	Protocol  string    `json:"proto"`     // tcp, udp, etc.
	Direction string    `json:"dir"`       // ingress, egress
	Packets   uint64    `json:"pkts"`
	Bytes     uint64    `json:"bytes"`
	LastSeen  time.Time `json:"last_seen"`
	State     string    `json:"state,omitempty"` // For TCP connections
}

// FlowCollector collects network flow information
type FlowCollector struct {
	flows      map[string]FlowInfo
	lastUpdate time.Time
	interval   time.Duration
	stopChan   chan struct{}
	running    bool
}

// NewFlowCollector creates a new flow collector
func NewFlowCollector(interval time.Duration) *FlowCollector {
	return &FlowCollector{
		flows:      make(map[string]FlowInfo),
		lastUpdate: time.Now(),
		interval:   interval,
		stopChan:   make(chan struct{}),
		running:    false,
	}
}

// Start starts collecting flows
func (fc *FlowCollector) Start() error {
	if fc.running {
		return fmt.Errorf("flow collector already running")
	}

	fc.running = true
	go fc.collectLoop()
	
	log.Printf("[visibility] Started flow collector (interval: %v)", fc.interval)
	return nil
}

// Stop stops collecting flows
func (fc *FlowCollector) Stop() error {
	if !fc.running {
		return fmt.Errorf("flow collector not running")
	}

	close(fc.stopChan)
	fc.running = false
	
	log.Printf("[visibility] Stopped flow collector")
	return nil
}

// collectLoop collects flows periodically
func (fc *FlowCollector) collectLoop() {
	ticker := time.NewTicker(fc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := fc.collectFlows(); err != nil {
				log.Printf("[visibility] Error collecting flows: %v", err)
			}
		case <-fc.stopChan:
			return
		}
	}
}

// collectFlows collects flows from /proc/net
func (fc *FlowCollector) collectFlows() error {
	// Collect TCP flows
	if err := fc.collectTCPFlows(); err != nil {
		log.Printf("[visibility] Error collecting TCP flows: %v", err)
	}

	// Collect UDP flows
	if err := fc.collectUDPFlows(); err != nil {
		log.Printf("[visibility] Error collecting UDP flows: %v", err)
	}

	fc.lastUpdate = time.Now()
	return nil
}

// collectTCPFlows collects TCP flows from /proc/net/tcp
func (fc *FlowCollector) collectTCPFlows() error {
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return fmt.Errorf("failed to open /proc/net/tcp: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // Skip header
		}

		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 11 {
			continue
		}

		// Parse TCP connection info
		flow, err := fc.parseTCPLine(fields)
		if err != nil {
			log.Printf("[visibility] Error parsing TCP line %d: %v", lineNum, err)
			continue
		}

		// Update flow
		fc.updateFlow(flow)
	}

	return scanner.Err()
}

// collectUDPFlows collects UDP flows from /proc/net/udp
func (fc *FlowCollector) collectUDPFlows() error {
	file, err := os.Open("/proc/net/udp")
	if err != nil {
		return fmt.Errorf("failed to open /proc/net/udp: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // Skip header
		}

		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 10 {
			continue
		}

		// Parse UDP connection info
		flow, err := fc.parseUDPLine(fields)
		if err != nil {
			log.Printf("[visibility] Error parsing UDP line %d: %v", lineNum, err)
			continue
		}

		// Update flow
		fc.updateFlow(flow)
	}

	return scanner.Err()
}

// parseTCPLine parses a TCP line from /proc/net/tcp
func (fc *FlowCollector) parseTCPLine(fields []string) (FlowInfo, error) {
	// Parse local address:port
	localAddr, err := fc.parseAddrPort(fields[1])
	if err != nil {
		return FlowInfo{}, fmt.Errorf("failed to parse local address: %w", err)
	}

	// Parse remote address:port
	remoteAddr, err := fc.parseAddrPort(fields[2])
	if err != nil {
		return FlowInfo{}, fmt.Errorf("failed to parse remote address: %w", err)
	}

	// Parse state
	state, err := strconv.ParseUint(fields[3], 16, 32)
	if err != nil {
		return FlowInfo{}, fmt.Errorf("failed to parse state: %w", err)
	}

	// Parse inode (we'll use this to find the PID)
	inode, err := strconv.ParseUint(fields[9], 10, 64)
	if err != nil {
		return FlowInfo{}, fmt.Errorf("failed to parse inode: %w", err)
	}

	// Find PID from inode
	pid, err := fc.findPIDByInode(inode)
	if err != nil {
		// This is common for system processes, use 0
		pid = 0
	}

	// Determine direction
	direction := "egress"
	if localAddr.Port == 0 || remoteAddr.Port == 0 {
		direction = "ingress"
	}

	flow := FlowInfo{
		PID:       pid,
		LAddr:     fmt.Sprintf("%s:%d", localAddr.IP, localAddr.Port),
		RAddr:     fmt.Sprintf("%s:%d", remoteAddr.IP, remoteAddr.Port),
		Protocol:  "tcp",
		Direction: direction,
		Packets:   1, // We don't have packet counts in /proc/net/tcp
		Bytes:     0, // We don't have byte counts in /proc/net/tcp
		LastSeen:  time.Now(),
		State:     fc.getTCPStateName(uint32(state)),
	}

	return flow, nil
}

// parseUDPLine parses a UDP line from /proc/net/udp
func (fc *FlowCollector) parseUDPLine(fields []string) (FlowInfo, error) {
	// Parse local address:port
	localAddr, err := fc.parseAddrPort(fields[1])
	if err != nil {
		return FlowInfo{}, fmt.Errorf("failed to parse local address: %w", err)
	}

	// Parse remote address:port
	remoteAddr, err := fc.parseAddrPort(fields[2])
	if err != nil {
		return FlowInfo{}, fmt.Errorf("failed to parse remote address: %w", err)
	}

	// Parse inode
	inode, err := strconv.ParseUint(fields[9], 10, 64)
	if err != nil {
		return FlowInfo{}, fmt.Errorf("failed to parse inode: %w", err)
	}

	// Find PID from inode
	pid, err := fc.findPIDByInode(inode)
	if err != nil {
		pid = 0
	}

	// Determine direction
	direction := "egress"
	if localAddr.Port == 0 || remoteAddr.Port == 0 {
		direction = "ingress"
	}

	flow := FlowInfo{
		PID:       pid,
		LAddr:     fmt.Sprintf("%s:%d", localAddr.IP, localAddr.Port),
		RAddr:     fmt.Sprintf("%s:%d", remoteAddr.IP, remoteAddr.Port),
		Protocol:  "udp",
		Direction: direction,
		Packets:   1,
		Bytes:     0,
		LastSeen:  time.Now(),
	}

	return flow, nil
}

// parseAddrPort parses an address:port string from /proc/net
func (fc *FlowCollector) parseAddrPort(addrPort string) (net.TCPAddr, error) {
	parts := strings.Split(addrPort, ":")
	if len(parts) != 2 {
		return net.TCPAddr{}, fmt.Errorf("invalid address:port format")
	}

	// Parse IP (hex format)
	ipHex, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return net.TCPAddr{}, fmt.Errorf("failed to parse IP: %w", err)
	}

	// Convert to dotted decimal
	ip := net.IPv4(
		byte(ipHex&0xFF),
		byte((ipHex>>8)&0xFF),
		byte((ipHex>>16)&0xFF),
		byte((ipHex>>24)&0xFF),
	)

	// Parse port (hex format)
	portHex, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return net.TCPAddr{}, fmt.Errorf("failed to parse port: %w", err)
	}

	return net.TCPAddr{
		IP:   ip,
		Port: int(portHex),
	}, nil
}

// findPIDByInode finds the PID that owns a given inode
func (fc *FlowCollector) findPIDByInode(inode uint64) (uint32, error) {
	// This is a simplified implementation
	// In practice, you'd need to scan /proc/*/fd/* for socket inodes
	// For now, return 0 (unknown PID)
	return 0, fmt.Errorf("PID lookup not implemented")
}

// getTCPStateName returns the TCP state name
func (fc *FlowCollector) getTCPStateName(state uint32) string {
	switch state {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	default:
		return "UNKNOWN"
	}
}

// updateFlow updates a flow in the collection
func (fc *FlowCollector) updateFlow(flow FlowInfo) {
	key := fmt.Sprintf("%s-%s-%s-%s", flow.LAddr, flow.RAddr, flow.Protocol, flow.Direction)
	
	if existing, exists := fc.flows[key]; exists {
		// Update existing flow
		existing.Packets++
		existing.LastSeen = flow.LastSeen
		fc.flows[key] = existing
	} else {
		// Add new flow
		fc.flows[key] = flow
	}
}

// GetFlows returns all collected flows
func (fc *FlowCollector) GetFlows() []FlowInfo {
	flows := make([]FlowInfo, 0, len(fc.flows))
	for _, flow := range fc.flows {
		flows = append(flows, flow)
	}
	return flows
}

// GetFlowsByPID returns flows for a specific PID
func (fc *FlowCollector) GetFlowsByPID(pid uint32) []FlowInfo {
	var flows []FlowInfo
	for _, flow := range fc.flows {
		if flow.PID == pid {
			flows = append(flows, flow)
		}
	}
	return flows
}

// GetFlowsByProtocol returns flows for a specific protocol
func (fc *FlowCollector) GetFlowsByProtocol(protocol string) []FlowInfo {
	var flows []FlowInfo
	for _, flow := range fc.flows {
		if flow.Protocol == protocol {
			flows = append(flows, flow)
		}
	}
	return flows
}

// GetFlowStats returns flow statistics
func (fc *FlowCollector) GetFlowStats() FlowStats {
	stats := FlowStats{
		TotalFlows:    len(fc.flows),
		TCPFlows:      0,
		UDPFlows:      0,
		EgressFlows:   0,
		IngressFlows:  0,
		TotalPackets:  0,
		TotalBytes:    0,
		LastUpdate:    fc.lastUpdate,
	}

	for _, flow := range fc.flows {
		stats.TotalPackets += flow.Packets
		stats.TotalBytes += flow.Bytes

		if flow.Protocol == "tcp" {
			stats.TCPFlows++
		} else if flow.Protocol == "udp" {
			stats.UDPFlows++
		}

		if flow.Direction == "egress" {
			stats.EgressFlows++
		} else if flow.Direction == "ingress" {
			stats.IngressFlows++
		}
	}

	return stats
}

// FlowStats contains flow statistics
type FlowStats struct {
	TotalFlows   int       `json:"total_flows"`
	TCPFlows     int       `json:"tcp_flows"`
	UDPFlows     int       `json:"udp_flows"`
	EgressFlows  int       `json:"egress_flows"`
	IngressFlows int       `json:"ingress_flows"`
	TotalPackets uint64    `json:"total_packets"`
	TotalBytes   uint64    `json:"total_bytes"`
	LastUpdate   time.Time `json:"last_update"`
}

// IsRunning returns true if the collector is running
func (fc *FlowCollector) IsRunning() bool {
	return fc.running
}

