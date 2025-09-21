package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"agents/aegis/internal/observability"
	"agents/aegis/internal/telemetry"
)

// DependencyAnalyzer analyzes dependencies between processes, services, and resources
type DependencyAnalyzer struct {
	processMonitor    *observability.ProcessMonitor
	serviceDiscovery  *observability.ServiceDiscovery
	auditLogger       *telemetry.AuditLogger
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	running           bool
	
	// Dependency graphs
	processGraph      *ProcessDependencyGraph
	serviceGraph      *ServiceDependencyGraph
	fileAccessGraph   *FileAccessGraph
	networkGraph      *NetworkDependencyGraph
	
	// Analysis results
	analysisResults   map[string]*AnalysisResult
	lastAnalysis      time.Time
	analysisInterval  time.Duration
}

// ProcessDependencyGraph represents dependencies between processes
type ProcessDependencyGraph struct {
	Nodes    map[uint32]*ProcessNode    `json:"nodes"`
	Edges    map[string]*ProcessEdge    `json:"edges"`
	Metadata map[string]interface{}     `json:"metadata"`
}

// ProcessNode represents a process in the dependency graph
type ProcessNode struct {
	PID           uint32                 `json:"pid"`
	PPID          uint32                 `json:"ppid"`
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	Namespace     string                 `json:"namespace"`
	StartTime     time.Time              `json:"start_time"`
	LastSeen      time.Time              `json:"last_seen"`
	Connections   []uint32               `json:"connections"`
	FileAccesses  []string               `json:"file_accesses"`
	Metadata      map[string]interface{} `json:"metadata"`
	RiskLevel     RiskLevel              `json:"risk_level"`
	Criticality   CriticalityLevel       `json:"criticality"`
}

// ProcessEdge represents a dependency between processes
type ProcessEdge struct {
	Source      uint32                 `json:"source"`
	Target      uint32                 `json:"target"`
	Type        DependencyType         `json:"type"`
	Weight      float64                `json:"weight"`
	Confidence  float64                `json:"confidence"`
	LastSeen    time.Time              `json:"last_seen"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ServiceDependencyGraph represents dependencies between services
type ServiceDependencyGraph struct {
	Nodes    map[string]*ServiceNode    `json:"nodes"`
	Edges    map[string]*ServiceEdge    `json:"edges"`
	Metadata map[string]interface{}     `json:"metadata"`
}

// ServiceNode represents a service in the dependency graph
type ServiceNode struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	Address       string                 `json:"address"`
	Port          int                    `json:"port"`
	Namespace     string                 `json:"namespace"`
	Environment   string                 `json:"environment"`
	HealthStatus  string                 `json:"health_status"`
	LastSeen      time.Time              `json:"last_seen"`
	Dependencies  []string               `json:"dependencies"`
	Consumers     []string               `json:"consumers"`
	Metadata      map[string]interface{} `json:"metadata"`
	RiskLevel     RiskLevel              `json:"risk_level"`
	Criticality   CriticalityLevel       `json:"criticality"`
}

// ServiceEdge represents a dependency between services
type ServiceEdge struct {
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Type        DependencyType         `json:"type"`
	Weight      float64                `json:"weight"`
	Latency     time.Duration          `json:"latency"`
	SuccessRate float64                `json:"success_rate"`
	LastCheck   time.Time              `json:"last_check"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// FileAccessGraph represents file access patterns
type FileAccessGraph struct {
	Nodes    map[string]*FileNode       `json:"nodes"`
	Edges    map[string]*FileEdge       `json:"edges"`
	Metadata map[string]interface{}     `json:"metadata"`
}

// FileNode represents a file in the access graph
type FileNode struct {
	Path        string                 `json:"path"`
	Type        string                 `json:"type"`
	Size        int64                  `json:"size"`
	Permissions string                 `json:"permissions"`
	Owner       string                 `json:"owner"`
	Group       string                 `json:"group"`
	LastAccess  time.Time              `json:"last_access"`
	AccessCount int                    `json:"access_count"`
	Processes   []uint32               `json:"processes"`
	Metadata    map[string]interface{} `json:"metadata"`
	RiskLevel   RiskLevel              `json:"risk_level"`
	Criticality CriticalityLevel       `json:"criticality"`
}

// FileEdge represents file access by a process
type FileEdge struct {
	ProcessID   uint32                 `json:"process_id"`
	FilePath    string                 `json:"file_path"`
	AccessType  string                 `json:"access_type"`
	Frequency   int                    `json:"frequency"`
	LastAccess  time.Time              `json:"last_access"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NetworkDependencyGraph represents network dependencies
type NetworkDependencyGraph struct {
	Nodes    map[string]*NetworkNode   `json:"nodes"`
	Edges    map[string]*NetworkEdge   `json:"edges"`
	Metadata map[string]interface{}    `json:"metadata"`
}

// NetworkNode represents a network endpoint
type NetworkNode struct {
	Address     string                 `json:"address"`
	Port        int                    `json:"port"`
	Protocol    string                 `json:"protocol"`
	Type        string                 `json:"type"`
	Connections []string               `json:"connections"`
	LastSeen    time.Time              `json:"last_seen"`
	Metadata    map[string]interface{} `json:"metadata"`
	RiskLevel   RiskLevel              `json:"risk_level"`
	Criticality CriticalityLevel       `json:"criticality"`
}

// NetworkEdge represents a network connection
type NetworkEdge struct {
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Protocol    string                 `json:"protocol"`
	Port        int                    `json:"port"`
	Bytes       int64                  `json:"bytes"`
	Packets     int64                  `json:"packets"`
	Duration    time.Duration          `json:"duration"`
	LastSeen    time.Time              `json:"last_seen"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AnalysisResult represents the result of dependency analysis
type AnalysisResult struct {
	Timestamp       time.Time              `json:"timestamp"`
	ProcessCount    int                    `json:"process_count"`
	ServiceCount    int                    `json:"service_count"`
	FileCount       int                    `json:"file_count"`
	NetworkCount    int                    `json:"network_count"`
	CriticalPaths   []CriticalPath         `json:"critical_paths"`
	RiskAreas       []RiskArea             `json:"risk_areas"`
	Recommendations []Recommendation       `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// CriticalPath represents a critical dependency path
type CriticalPath struct {
	Path        []string               `json:"path"`
	Type        string                 `json:"type"`
	Criticality CriticalityLevel       `json:"criticality"`
	RiskLevel   RiskLevel              `json:"risk_level"`
	Impact      string                 `json:"impact"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RiskArea represents an area of risk in the system
type RiskArea struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Severity    RiskLevel              `json:"severity"`
	Affected    []string               `json:"affected"`
	Mitigation  string                 `json:"mitigation"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Recommendation represents a recommendation for improvement
type Recommendation struct {
	Type        string                 `json:"type"`
	Priority    PriorityLevel          `json:"priority"`
	Description string                 `json:"description"`
	Action      string                 `json:"action"`
	Impact      string                 `json:"impact"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Enums
type DependencyType string
const (
	DepTypeParentChild    DependencyType = "parent_child"
	DepTypeCommunication  DependencyType = "communication"
	DepTypeFileAccess     DependencyType = "file_access"
	DepTypeNetwork        DependencyType = "network"
	DepTypeService        DependencyType = "service"
	DepTypeResource       DependencyType = "resource"
)

type RiskLevel string
const (
	RiskLow       RiskLevel = "low"
	RiskMedium    RiskLevel = "medium"
	RiskHigh      RiskLevel = "high"
	RiskCritical  RiskLevel = "critical"
)

type CriticalityLevel string
const (
	CriticalityLow       CriticalityLevel = "low"
	CriticalityMedium    CriticalityLevel = "medium"
	CriticalityHigh      CriticalityLevel = "high"
	CriticalityCritical  CriticalityLevel = "critical"
)

type PriorityLevel string
const (
	PriorityLow       PriorityLevel = "low"
	PriorityMedium    PriorityLevel = "medium"
	PriorityHigh      PriorityLevel = "high"
	PriorityCritical  PriorityLevel = "critical"
)

// NewDependencyAnalyzer creates a new dependency analyzer
func NewDependencyAnalyzer(processMonitor *observability.ProcessMonitor, serviceDiscovery *observability.ServiceDiscovery, auditLogger *telemetry.AuditLogger) *DependencyAnalyzer {
	ctx, cancel := context.WithCancel(context.Background())
	
	da := &DependencyAnalyzer{
		processMonitor:   processMonitor,
		serviceDiscovery: serviceDiscovery,
		auditLogger:      auditLogger,
		ctx:              ctx,
		cancel:           cancel,
		analysisResults:  make(map[string]*AnalysisResult),
		analysisInterval: 60 * time.Second, // Analyze every minute
		
		// Initialize graphs
		processGraph: &ProcessDependencyGraph{
			Nodes:    make(map[uint32]*ProcessNode),
			Edges:    make(map[string]*ProcessEdge),
			Metadata: make(map[string]interface{}),
		},
		serviceGraph: &ServiceDependencyGraph{
			Nodes:    make(map[string]*ServiceNode),
			Edges:    make(map[string]*ServiceEdge),
			Metadata: make(map[string]interface{}),
		},
		fileAccessGraph: &FileAccessGraph{
			Nodes:    make(map[string]*FileNode),
			Edges:    make(map[string]*FileEdge),
			Metadata: make(map[string]interface{}),
		},
		networkGraph: &NetworkDependencyGraph{
			Nodes:    make(map[string]*NetworkNode),
			Edges:    make(map[string]*NetworkEdge),
			Metadata: make(map[string]interface{}),
		},
	}
	
	log.Printf("[dependency_analyzer] Dependency analyzer initialized")
	return da
}

// Start starts the dependency analyzer
func (da *DependencyAnalyzer) Start() error {
	da.mu.Lock()
	defer da.mu.Unlock()
	
	if da.running {
		return fmt.Errorf("dependency analyzer already running")
	}
	
	da.running = true
	
	// Start analysis goroutine
	go da.performAnalysis()
	
	log.Printf("[dependency_analyzer] Dependency analyzer started")
	
	// Log startup event
	da.auditLogger.LogSystemEvent("dependency_analyzer_start", "Dependency analyzer started", map[string]interface{}{
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"analysis_interval": da.analysisInterval.String(),
	})
	
	return nil
}

// Stop stops the dependency analyzer
func (da *DependencyAnalyzer) Stop() error {
	da.mu.Lock()
	defer da.mu.Unlock()
	
	if !da.running {
		return fmt.Errorf("dependency analyzer not running")
	}
	
	da.cancel()
	da.running = false
	
	log.Printf("[dependency_analyzer] Dependency analyzer stopped")
	
	// Log shutdown event
	da.auditLogger.LogSystemEvent("dependency_analyzer_stop", "Dependency analyzer stopped", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	
	return nil
}

// performAnalysis performs continuous dependency analysis
func (da *DependencyAnalyzer) performAnalysis() {
	ticker := time.NewTicker(da.analysisInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			da.analyzeDependencies()
		case <-da.ctx.Done():
			return
		}
	}
}

// analyzeDependencies performs the main dependency analysis
func (da *DependencyAnalyzer) analyzeDependencies() {
	start := time.Now()
	
	// Analyze process dependencies
	da.analyzeProcessDependencies()
	
	// Analyze service dependencies
	da.analyzeServiceDependencies()
	
	// Analyze file access patterns
	da.analyzeFileAccessPatterns()
	
	// Analyze network dependencies
	da.analyzeNetworkDependencies()
	
	// Generate analysis results
	result := da.generateAnalysisResult()
	
	// Store results
	da.mu.Lock()
	da.analysisResults[result.Timestamp.Format(time.RFC3339)] = result
	da.lastAnalysis = result.Timestamp
	da.mu.Unlock()
	
	duration := time.Since(start)
	log.Printf("[dependency_analyzer] Analysis completed in %v", duration)
	
	// Log analysis completion
	da.auditLogger.LogCustomEvent(telemetry.EventTypeAnalysisEvent, telemetry.SeverityInfo,
		"Dependency analysis completed",
		map[string]interface{}{
			"duration_ms":     duration.Milliseconds(),
			"process_count":   result.ProcessCount,
			"service_count":   result.ServiceCount,
			"file_count":      result.FileCount,
			"network_count":   result.NetworkCount,
			"critical_paths":  len(result.CriticalPaths),
			"risk_areas":      len(result.RiskAreas),
			"recommendations": len(result.Recommendations),
		})
}

// analyzeProcessDependencies analyzes dependencies between processes
func (da *DependencyAnalyzer) analyzeProcessDependencies() {
	// Get all processes from process monitor
	processes, err := da.processMonitor.GetAllProcesses()
	if err != nil {
		log.Printf("[dependency_analyzer] Failed to get processes: %v", err)
		return
	}
	
	da.mu.Lock()
	defer da.mu.Unlock()
	
	// Clear existing process graph
	da.processGraph.Nodes = make(map[uint32]*ProcessNode)
	da.processGraph.Edges = make(map[string]*ProcessEdge)
	
	// Build process nodes
	for _, process := range processes {
		node := &ProcessNode{
			PID:          process.PID,
			PPID:         process.PPID,
			Name:         string(process.Comm[:]),
			Type:         da.classifyProcessType(process),
			Namespace:    fmt.Sprintf("ns_%d", process.NamespaceID),
			StartTime:    time.Unix(0, int64(process.StartTime)),
			LastSeen:     time.Unix(0, int64(process.LastSeen)),
			Connections:  []uint32{},
			FileAccesses: []string{},
			Metadata:     make(map[string]interface{}),
			RiskLevel:    da.assessProcessRisk(process),
			Criticality:  da.assessProcessCriticality(process),
		}
		
		da.processGraph.Nodes[process.PID] = node
	}
	
	// Build process edges (parent-child relationships)
	for _, process := range processes {
		if process.PPID != 0 {
			edgeKey := fmt.Sprintf("%d->%d", process.PPID, process.PID)
			edge := &ProcessEdge{
				Source:     process.PPID,
				Target:     process.PID,
				Type:       DepTypeParentChild,
				Weight:     1.0,
				Confidence: 1.0,
				LastSeen:   time.Unix(0, int64(process.LastSeen)),
				Metadata:   make(map[string]interface{}),
			}
			da.processGraph.Edges[edgeKey] = edge
		}
	}
	
	// Analyze process communication patterns
	da.analyzeProcessCommunication()
}

// analyzeServiceDependencies analyzes dependencies between services
func (da *DependencyAnalyzer) analyzeServiceDependencies() {
	// Get all services from service discovery
	services := da.serviceDiscovery.GetServices()
	
	da.mu.Lock()
	defer da.mu.Unlock()
	
	// Clear existing service graph
	da.serviceGraph.Nodes = make(map[string]*ServiceNode)
	da.serviceGraph.Edges = make(map[string]*ServiceEdge)
	
	// Build service nodes
	for id, service := range services {
		node := &ServiceNode{
			ID:           service.ID,
			Name:         service.Name,
			Type:         service.Type,
			Address:      service.Address,
			Port:         service.Port,
			Namespace:    service.Namespace,
			Environment:  service.Environment,
			HealthStatus: string(service.HealthStatus),
			LastSeen:     service.LastSeen,
			Dependencies: []string{},
			Consumers:    []string{},
			Metadata:     service.Metadata,
			RiskLevel:    da.assessServiceRisk(service),
			Criticality:  da.assessServiceCriticality(service),
		}
		
		da.serviceGraph.Nodes[id] = node
	}
	
	// Build service edges from dependencies
	for serviceID, dependencies := range da.serviceDiscovery.GetServiceDependencies(serviceID) {
		for _, dep := range dependencies {
			edgeKey := fmt.Sprintf("%s->%s", serviceID, dep.TargetServiceID)
			edge := &ServiceEdge{
				Source:      serviceID,
				Target:      dep.TargetServiceID,
				Type:        DepTypeService,
				Weight:      float64(dep.Weight),
				Latency:     dep.Latency,
				SuccessRate: dep.SuccessRate,
				LastCheck:   dep.LastCheck,
				Metadata:    dep.Metadata,
			}
			da.serviceGraph.Edges[edgeKey] = edge
		}
	}
}

// analyzeFileAccessPatterns analyzes file access patterns
func (da *DependencyAnalyzer) analyzeFileAccessPatterns() {
	// Get all processes to analyze file access
	processes, err := da.processMonitor.GetAllProcesses()
	if err != nil {
		log.Printf("[dependency_analyzer] Failed to get processes for file analysis: %v", err)
		return
	}
	
	da.mu.Lock()
	defer da.mu.Unlock()
	
	// Clear existing file graph
	da.fileAccessGraph.Nodes = make(map[string]*FileNode)
	da.fileAccessGraph.Edges = make(map[string]*FileEdge)
	
	// Analyze file access for each process
	for _, process := range processes {
		fileAccesses, err := da.processMonitor.GetProcessFileAccess(process.PID)
		if err != nil {
			continue // Skip processes without file access data
		}
		
		for _, fileAccess := range fileAccesses {
			filePath := string(fileAccess.FilePath[:])
			if filePath == "" {
				continue
			}
			
			// Create or update file node
			if _, exists := da.fileAccessGraph.Nodes[filePath]; !exists {
				da.fileAccessGraph.Nodes[filePath] = &FileNode{
					Path:        filePath,
					Type:        da.classifyFileType(filePath),
					Size:        int64(fileAccess.FileSize),
					Permissions: fmt.Sprintf("%o", fileAccess.FileMode),
					Owner:       fmt.Sprintf("%d", fileAccess.FileUID),
					Group:       fmt.Sprintf("%d", fileAccess.FileGID),
					LastAccess:  time.Unix(0, int64(fileAccess.Timestamp)),
					AccessCount: 1,
					Processes:   []uint32{process.PID},
					Metadata:    make(map[string]interface{}),
					RiskLevel:   da.assessFileRisk(filePath),
					Criticality: da.assessFileCriticality(filePath),
				}
			} else {
				// Update existing file node
				node := da.fileAccessGraph.Nodes[filePath]
				node.AccessCount++
				node.LastAccess = time.Unix(0, int64(fileAccess.Timestamp))
				node.Processes = append(node.Processes, process.PID)
			}
			
			// Create file access edge
			edgeKey := fmt.Sprintf("%d->%s", process.PID, filePath)
			edge := &FileEdge{
				ProcessID:  process.PID,
				FilePath:   filePath,
				AccessType: da.getAccessType(fileAccess.AccessMode),
				Frequency:  1,
				LastAccess: time.Unix(0, int64(fileAccess.Timestamp)),
				Metadata:   make(map[string]interface{}),
			}
			da.fileAccessGraph.Edges[edgeKey] = edge
		}
	}
}

// analyzeNetworkDependencies analyzes network dependencies
func (da *DependencyAnalyzer) analyzeNetworkDependencies() {
	// Get all processes to analyze network connections
	processes, err := da.processMonitor.GetAllProcesses()
	if err != nil {
		log.Printf("[dependency_analyzer] Failed to get processes for network analysis: %v", err)
		return
	}
	
	da.mu.Lock()
	defer da.mu.Unlock()
	
	// Clear existing network graph
	da.networkGraph.Nodes = make(map[string]*NetworkNode)
	da.networkGraph.Edges = make(map[string]*NetworkEdge)
	
	// Analyze network connections for each process
	for _, process := range processes {
		connections, err := da.processMonitor.GetProcessNetworkConnections(process.PID)
		if err != nil {
			continue // Skip processes without network data
		}
		
		for _, conn := range connections {
			sourceAddr := fmt.Sprintf("%s:%d", da.formatIP(conn.SrcIP), conn.SrcPort)
			targetAddr := fmt.Sprintf("%s:%d", da.formatIP(conn.DstIP), conn.DstPort)
			
			// Create network nodes
			if _, exists := da.networkGraph.Nodes[sourceAddr]; !exists {
				da.networkGraph.Nodes[sourceAddr] = &NetworkNode{
					Address:     da.formatIP(conn.SrcIP),
					Port:        int(conn.SrcPort),
					Protocol:    da.getProtocolName(conn.Protocol),
					Type:        da.classifyNetworkType(conn.SrcIP, conn.SrcPort),
					Connections: []string{targetAddr},
					LastSeen:    time.Unix(0, int64(conn.LastActivity)),
					Metadata:    make(map[string]interface{}),
					RiskLevel:   da.assessNetworkRisk(conn.SrcIP, conn.SrcPort),
					Criticality: da.assessNetworkCriticality(conn.SrcIP, conn.SrcPort),
				}
			}
			
			if _, exists := da.networkGraph.Nodes[targetAddr]; !exists {
				da.networkGraph.Nodes[targetAddr] = &NetworkNode{
					Address:     da.formatIP(conn.DstIP),
					Port:        int(conn.DstPort),
					Protocol:    da.getProtocolName(conn.Protocol),
					Type:        da.classifyNetworkType(conn.DstIP, conn.DstPort),
					Connections: []string{sourceAddr},
					LastSeen:    time.Unix(0, int64(conn.LastActivity)),
					Metadata:    make(map[string]interface{}),
					RiskLevel:   da.assessNetworkRisk(conn.DstIP, conn.DstPort),
					Criticality: da.assessNetworkCriticality(conn.DstIP, conn.DstPort),
				}
			}
			
			// Create network edge
			edgeKey := fmt.Sprintf("%s->%s", sourceAddr, targetAddr)
			edge := &NetworkEdge{
				Source:   sourceAddr,
				Target:   targetAddr,
				Protocol: da.getProtocolName(conn.Protocol),
				Port:     int(conn.DstPort),
				Bytes:    int64(conn.BytesSent + conn.BytesRecv),
				Packets:  int64(conn.PacketsSent + conn.PacketsRecv),
				Duration: time.Duration(conn.LastActivity - conn.StartTime),
				LastSeen: time.Unix(0, int64(conn.LastActivity)),
				Metadata: make(map[string]interface{}),
			}
			da.networkGraph.Edges[edgeKey] = edge
		}
	}
}

// generateAnalysisResult generates the final analysis result
func (da *DependencyAnalyzer) generateAnalysisResult() *AnalysisResult {
	result := &AnalysisResult{
		Timestamp:       time.Now(),
		ProcessCount:    len(da.processGraph.Nodes),
		ServiceCount:    len(da.serviceGraph.Nodes),
		FileCount:       len(da.fileAccessGraph.Nodes),
		NetworkCount:    len(da.networkGraph.Nodes),
		CriticalPaths:   da.findCriticalPaths(),
		RiskAreas:       da.identifyRiskAreas(),
		Recommendations: da.generateRecommendations(),
		Metadata:        make(map[string]interface{}),
	}
	
	return result
}

// Helper methods for classification and assessment
func (da *DependencyAnalyzer) classifyProcessType(process observability.ProcessInfo) string {
	name := string(process.Comm[:])
	
	// Classify based on process name
	if strings.Contains(name, "nginx") || strings.Contains(name, "apache") {
		return "webserver"
	} else if strings.Contains(name, "postgres") || strings.Contains(name, "mysql") {
		return "database"
	} else if strings.Contains(name, "redis") || strings.Contains(name, "memcached") {
		return "cache"
	} else if strings.Contains(name, "kube") || strings.Contains(name, "docker") {
		return "container_runtime"
	} else if strings.Contains(name, "systemd") || strings.Contains(name, "init") {
		return "system"
	}
	
	return "application"
}

func (da *DependencyAnalyzer) assessProcessRisk(process observability.ProcessInfo) RiskLevel {
	// Assess risk based on process characteristics
	if process.UID == 0 { // Root process
		return RiskHigh
	} else if process.Capabilities > 0 { // Process with capabilities
		return RiskMedium
	}
	
	return RiskLow
}

func (da *DependencyAnalyzer) assessProcessCriticality(process observability.ProcessInfo) CriticalityLevel {
	// Assess criticality based on process type
	processType := da.classifyProcessType(process)
	
	switch processType {
	case "system", "database", "webserver":
		return CriticalityHigh
	case "cache", "container_runtime":
		return CriticalityMedium
	default:
		return CriticalityLow
	}
}

func (da *DependencyAnalyzer) assessServiceRisk(service *observability.Service) RiskLevel {
	// Assess risk based on service characteristics
	if service.HealthStatus == observability.HealthUnhealthy {
		return RiskHigh
	} else if service.HealthStatus == observability.HealthDegraded {
		return RiskMedium
	}
	
	return RiskLow
}

func (da *DependencyAnalyzer) assessServiceCriticality(service *observability.Service) CriticalityLevel {
	// Assess criticality based on service type
	switch service.Type {
	case "database", "webserver", "api":
		return CriticalityHigh
	case "cache", "monitoring":
		return CriticalityMedium
	default:
		return CriticalityLow
	}
}

func (da *DependencyAnalyzer) classifyFileType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	
	switch ext {
	case ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json":
		return "config"
	case ".log", ".out", ".err":
		return "log"
	case ".db", ".sqlite", ".sqlite3":
		return "database"
	case ".key", ".pem", ".crt", ".p12":
		return "certificate"
	case ".sh", ".py", ".go", ".js", ".java":
		return "script"
	default:
		return "data"
	}
}

func (da *DependencyAnalyzer) assessFileRisk(filePath string) RiskLevel {
	// Assess risk based on file path and type
	if strings.Contains(filePath, "/etc/") || strings.Contains(filePath, "/root/") {
		return RiskHigh
	} else if strings.Contains(filePath, "/var/log/") || strings.Contains(filePath, "/tmp/") {
		return RiskMedium
	}
	
	return RiskLow
}

func (da *DependencyAnalyzer) assessFileCriticality(filePath string) CriticalityLevel {
	// Assess criticality based on file path
	if strings.Contains(filePath, "/etc/") || strings.Contains(filePath, "/bin/") || strings.Contains(filePath, "/sbin/") {
		return CriticalityHigh
	} else if strings.Contains(filePath, "/var/") || strings.Contains(filePath, "/opt/") {
		return CriticalityMedium
	}
	
	return CriticalityLow
}

func (da *DependencyAnalyzer) assessNetworkRisk(ip uint32, port uint16) RiskLevel {
	// Assess risk based on IP and port
	if port == 22 || port == 3389 || port == 5985 { // SSH, RDP, WinRM
		return RiskHigh
	} else if port == 80 || port == 443 { // HTTP/HTTPS
		return RiskMedium
	}
	
	return RiskLow
}

func (da *DependencyAnalyzer) assessNetworkCriticality(ip uint32, port uint16) CriticalityLevel {
	// Assess criticality based on port
	if port == 80 || port == 443 || port == 22 { // Common services
		return CriticalityHigh
	} else if port >= 8000 && port <= 8999 { // Application ports
		return CriticalityMedium
	}
	
	return CriticalityLow
}

func (da *DependencyAnalyzer) getAccessType(accessMode uint32) string {
	switch accessMode {
	case 0: // O_RDONLY
		return "read"
	case 1: // O_WRONLY
		return "write"
	case 2: // O_RDWR
		return "read_write"
	default:
		return "unknown"
	}
}

func (da *DependencyAnalyzer) getProtocolName(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return "unknown"
	}
}

func (da *DependencyAnalyzer) classifyNetworkType(ip uint32, port uint16) string {
	// Classify based on port
	if port == 80 || port == 443 {
		return "web"
	} else if port == 22 {
		return "ssh"
	} else if port == 3306 || port == 5432 {
		return "database"
	} else if port == 6379 {
		return "cache"
	}
	
	return "application"
}

func (da *DependencyAnalyzer) formatIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", 
		(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}

// Analysis methods
func (da *DependencyAnalyzer) findCriticalPaths() []CriticalPath {
	var criticalPaths []CriticalPath
	
	// Find critical paths in process graph
	da.findProcessCriticalPaths(&criticalPaths)
	
	// Find critical paths in service graph
	da.findServiceCriticalPaths(&criticalPaths)
	
	return criticalPaths
}

func (da *DependencyAnalyzer) findProcessCriticalPaths(criticalPaths *[]CriticalPath) {
	// Find long dependency chains
	for _, edge := range da.processGraph.Edges {
		if edge.Type == DepTypeParentChild {
			path := da.buildPath(edge.Source, edge.Target, DepTypeParentChild)
			if len(path) > 3 { // Long chain
				*criticalPaths = append(*criticalPaths, CriticalPath{
					Path:        path,
					Type:        "process_chain",
					Criticality: CriticalityHigh,
					RiskLevel:   RiskMedium,
					Impact:      "Process failure could cascade",
					Metadata:    make(map[string]interface{}),
				})
			}
		}
	}
}

func (da *DependencyAnalyzer) findServiceCriticalPaths(criticalPaths *[]CriticalPath) {
	// Find service dependency chains
	for _, edge := range da.serviceGraph.Edges {
		if edge.Type == DepTypeService {
			path := da.buildServicePath(edge.Source, edge.Target)
			if len(path) > 2 { // Service chain
				*criticalPaths = append(*criticalPaths, CriticalPath{
					Path:        path,
					Type:        "service_chain",
					Criticality: CriticalityHigh,
					RiskLevel:   RiskMedium,
					Impact:      "Service failure could cascade",
					Metadata:    make(map[string]interface{}),
				})
			}
		}
	}
}

func (da *DependencyAnalyzer) buildPath(source, target uint32, depType DependencyType) []string {
	// Simplified path building - in reality would use graph algorithms
	return []string{fmt.Sprintf("process_%d", source), fmt.Sprintf("process_%d", target)}
}

func (da *DependencyAnalyzer) buildServicePath(source, target string) []string {
	// Simplified service path building
	return []string{source, target}
}

func (da *DependencyAnalyzer) identifyRiskAreas() []RiskArea {
	var riskAreas []RiskArea
	
	// Identify high-risk processes
	for _, node := range da.processGraph.Nodes {
		if node.RiskLevel == RiskHigh || node.RiskLevel == RiskCritical {
			riskAreas = append(riskAreas, RiskArea{
				Type:        "high_risk_process",
				Description: fmt.Sprintf("Process %s (PID %d) has high risk level", node.Name, node.PID),
				Severity:    node.RiskLevel,
				Affected:    []string{fmt.Sprintf("process_%d", node.PID)},
				Mitigation:  "Review process permissions and capabilities",
				Metadata:    make(map[string]interface{}),
			})
		}
	}
	
	// Identify unhealthy services
	for _, node := range da.serviceGraph.Nodes {
		if node.HealthStatus == "unhealthy" {
			riskAreas = append(riskAreas, RiskArea{
				Type:        "unhealthy_service",
				Description: fmt.Sprintf("Service %s is unhealthy", node.Name),
				Severity:    RiskHigh,
				Affected:    []string{node.ID},
				Mitigation:  "Investigate service health and restart if necessary",
				Metadata:    make(map[string]interface{}),
			})
		}
	}
	
	return riskAreas
}

func (da *DependencyAnalyzer) generateRecommendations() []Recommendation {
	var recommendations []Recommendation
	
	// Generate recommendations based on analysis
	if len(da.processGraph.Nodes) > 100 {
		recommendations = append(recommendations, Recommendation{
			Type:        "process_optimization",
			Priority:    PriorityMedium,
			Description: "High number of processes detected",
			Action:      "Consider process consolidation or optimization",
			Impact:      "Improved resource utilization",
			Metadata:    make(map[string]interface{}),
		})
	}
	
	if len(da.serviceGraph.Nodes) > 50 {
		recommendations = append(recommendations, Recommendation{
			Type:        "service_optimization",
			Priority:    PriorityMedium,
			Description: "High number of services detected",
			Action:      "Consider service consolidation or load balancing",
			Impact:      "Improved service management",
			Metadata:    make(map[string]interface{}),
		})
	}
	
	return recommendations
}

// Public methods for accessing analysis results
func (da *DependencyAnalyzer) GetProcessGraph() *ProcessDependencyGraph {
	da.mu.RLock()
	defer da.mu.RUnlock()
	return da.processGraph
}

func (da *DependencyAnalyzer) GetServiceGraph() *ServiceDependencyGraph {
	da.mu.RLock()
	defer da.mu.RUnlock()
	return da.serviceGraph
}

func (da *DependencyAnalyzer) GetFileAccessGraph() *FileAccessGraph {
	da.mu.RLock()
	defer da.mu.RUnlock()
	return da.fileAccessGraph
}

func (da *DependencyAnalyzer) GetNetworkGraph() *NetworkDependencyGraph {
	da.mu.RLock()
	defer da.mu.RUnlock()
	return da.networkGraph
}

func (da *DependencyAnalyzer) GetAnalysisResults() map[string]*AnalysisResult {
	da.mu.RLock()
	defer da.mu.RUnlock()
	return da.analysisResults
}

func (da *DependencyAnalyzer) GetLastAnalysis() *AnalysisResult {
	da.mu.RLock()
	defer da.mu.RUnlock()
	return da.analysisResults[da.lastAnalysis.Format(time.RFC3339)]
}

// Close closes the dependency analyzer
func (da *DependencyAnalyzer) Close() error {
	return da.Stop()
}
