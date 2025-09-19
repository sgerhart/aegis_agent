package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Policy edge structure for network segmentation
type PolicyEdge struct {
	SrcIP      uint32 `json:"src_ip"`
	DstIP      uint32 `json:"dst_ip"`
	SrcMask    uint32 `json:"src_mask"`
	DstMask    uint32 `json:"dst_mask"`
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	Protocol   uint8  `json:"protocol"`
	Action     uint8  `json:"action"` // 0=BLOCK, 1=ALLOW, 2=LOG
	Priority   uint8  `json:"priority"`
	ProcessUID uint32 `json:"process_uid"`
	ProcessGID uint32 `json:"process_gid"`
	Timestamp  uint64 `json:"timestamp"`
}

// LPM entry for CIDR allowlists
type AllowCIDR struct {
	PrefixLen uint32 `json:"prefix_len"`
	IP        uint32 `json:"ip"`
	Action    uint8  `json:"action"` // 0=BLOCK, 1=ALLOW
	Priority  uint8  `json:"priority"`
	Timestamp uint64 `json:"timestamp"`
}

// Policy statistics
type PolicyStats struct {
	TotalPolicies      uint64   `json:"total_policies"`
	ActivePolicies     uint64   `json:"active_policies"`
	BlockedConnections uint64   `json:"blocked_connections"`
	AllowedConnections uint64   `json:"allowed_connections"`
	LoggedConnections  uint64   `json:"logged_connections"`
	PolicyHits         [256]uint64 `json:"policy_hits"`
}

func main() {
	// Remove memlock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock rlimit: %v", err)
	}

	// Get the current directory to find the bpf objects
	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get working directory: %v", err)
	}
	
	// Find the bpf objects (go up to project root)
	projectRoot := wd
	for {
		if _, err := os.Stat(filepath.Join(projectRoot, "bpf")); err == nil {
			break
		}
		parent := filepath.Dir(projectRoot)
		if parent == projectRoot {
			log.Fatalf("Could not find bpf directory")
		}
		projectRoot = parent
	}
	
	policyMapsObjectPath := filepath.Join(projectRoot, "bpf", "bpf", "seg_policy_maps.o")
	
	fmt.Println("=== AegisFlux Policy Maps Pinning and Seeding ===")
	
	// Load the policy maps eBPF program
	spec, err := ebpf.LoadCollectionSpec(policyMapsObjectPath)
	if err != nil {
		log.Fatalf("Failed to load policy maps spec: %v", err)
	}
	
	// Load the collection
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to load policy maps collection: %v", err)
	}
	defer collection.Close()
	
	fmt.Println("✓ Loaded policy maps eBPF collection")
	
	// Create the aegis directory
	aegisDir := "/sys/fs/bpf/aegis"
	if err := os.MkdirAll(aegisDir, 0755); err != nil {
		log.Fatalf("Failed to create aegis directory: %v", err)
	}
	fmt.Printf("✓ Created directory: %s\n", aegisDir)
	
	// Pin the maps
	fmt.Println("\n=== Pinning Maps ===")
	
	// Pin policy_edges map
	policyEdgesMap, ok := collection.Maps["policy_edges"]
	if !ok {
		log.Fatalf("policy_edges map not found")
	}
	
	if err := policyEdgesMap.Pin(filepath.Join(aegisDir, "policy_edges")); err != nil {
		log.Fatalf("Failed to pin policy_edges map: %v", err)
	}
	fmt.Println("✓ Pinned policy_edges map")
	
	// Pin allow_lpm4 map
	allowLPM4Map, ok := collection.Maps["allow_lpm4"]
	if !ok {
		log.Fatalf("allow_lpm4 map not found")
	}
	
	if err := allowLPM4Map.Pin(filepath.Join(aegisDir, "allow_lpm4")); err != nil {
		log.Fatalf("Failed to pin allow_lpm4 map: %v", err)
	}
	fmt.Println("✓ Pinned allow_lpm4 map")
	
	// Pin policy_stats_map
	policyStatsMap, ok := collection.Maps["policy_stats_map"]
	if !ok {
		log.Fatalf("policy_stats_map not found")
	}
	
	if err := policyStatsMap.Pin(filepath.Join(aegisDir, "policy_stats_map")); err != nil {
		log.Fatalf("Failed to pin policy_stats_map: %v", err)
	}
	fmt.Println("✓ Pinned policy_stats_map")
	
	// Seed the maps with test data
	fmt.Println("\n=== Seeding Maps ===")
	
	// Add a test policy edge
	edge := PolicyEdge{
		SrcIP:      0xC0A80100, // 192.168.1.0
		DstIP:      0xC0A80200, // 192.168.2.0
		SrcMask:    0xFFFFFF00, // 255.255.255.0
		DstMask:    0xFFFFFF00, // 255.255.255.0
		SrcPort:    80,
		DstPort:    443,
		Protocol:   6, // TCP
		Action:     1, // ALLOW
		Priority:   10,
		ProcessUID: 1000,
		ProcessGID: 1000,
		Timestamp:  1234567890,
	}
	
	key := uint32(1)
	if err := policyEdgesMap.Put(key, edge); err != nil {
		log.Fatalf("Failed to add policy edge: %v", err)
	}
	fmt.Println("✓ Added policy edge (key=1)")
	
	// Add a test allow CIDR
	cidr := AllowCIDR{
		PrefixLen: 24,
		IP:        0xC0A80100, // 192.168.1.0/24
		Action:    1,          // ALLOW
		Priority:  5,
		Timestamp: 1234567890,
	}
	
	if err := allowLPM4Map.Put(cidr, uint8(1)); err != nil {
		log.Fatalf("Failed to add allow CIDR: %v", err)
	}
	fmt.Println("✓ Added allow CIDR (192.168.1.0/24)")
	
	// Initialize policy stats
	stats := PolicyStats{
		TotalPolicies:      2,
		ActivePolicies:     2,
		BlockedConnections: 0,
		AllowedConnections: 0,
		LoggedConnections:  0,
	}
	
	statsKey := uint32(0)
	if err := policyStatsMap.Put(statsKey, stats); err != nil {
		log.Fatalf("Failed to initialize policy stats: %v", err)
	}
	fmt.Println("✓ Initialized policy stats")
	
	// Verify the data
	fmt.Println("\n=== Verifying Data ===")
	
	// Verify policy edge
	var retrievedEdge PolicyEdge
	if err := policyEdgesMap.Lookup(key, &retrievedEdge); err != nil {
		log.Fatalf("Failed to retrieve policy edge: %v", err)
	}
	fmt.Printf("✓ Retrieved policy edge: %+v\n", retrievedEdge)
	
	// Verify allow CIDR
	var retrievedValue uint8
	if err := allowLPM4Map.Lookup(cidr, &retrievedValue); err != nil {
		log.Fatalf("Failed to retrieve allow CIDR: %v", err)
	}
	fmt.Printf("✓ Retrieved allow CIDR: %+v (value=%d)\n", cidr, retrievedValue)
	
	// Verify policy stats
	var retrievedStats PolicyStats
	if err := policyStatsMap.Lookup(statsKey, &retrievedStats); err != nil {
		log.Fatalf("Failed to retrieve policy stats: %v", err)
	}
	fmt.Printf("✓ Retrieved policy stats: %+v\n", retrievedStats)
	
	fmt.Println("\n=== Test Summary ===")
	fmt.Println("✓ Pinned maps created under /sys/fs/bpf/aegis/")
	fmt.Println("✓ Test data seeded successfully")
	fmt.Println("✓ Maps can be read and written")
	fmt.Println("✓ Ready for policy enforcement")
	
	// Keep the program running to maintain the pinned maps
	fmt.Println("\nMaps are pinned and ready. Press Ctrl+C to exit.")
	select {}
}
