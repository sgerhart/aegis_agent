package analysis

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"agents/aegis/internal/telemetry"
)

// DependencyVisualizer provides visualization capabilities for dependency analysis
type DependencyVisualizer struct {
	analyzer    *DependencyAnalyzer
	auditLogger *telemetry.AuditLogger
}

// VisualizationConfig holds configuration for visualization
type VisualizationConfig struct {
	Format          string        `json:"format"` // json, dot, mermaid, text
	IncludeMetadata bool          `json:"include_metadata"`
	MaxNodes        int           `json:"max_nodes"`
	MaxEdges        int           `json:"max_edges"`
	FilterByRisk    []RiskLevel   `json:"filter_by_risk"`
	FilterByType    []string      `json:"filter_by_type"`
	GroupBy         string        `json:"group_by"` // namespace, type, risk_level
}

// GraphVisualization represents a visual representation of a dependency graph
type GraphVisualization struct {
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Nodes       []VisualNode           `json:"nodes"`
	Edges       []VisualEdge           `json:"edges"`
	Groups      []VisualGroup          `json:"groups,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
	GeneratedAt time.Time              `json:"generated_at"`
}

// VisualNode represents a node in the visualization
type VisualNode struct {
	ID          string                 `json:"id"`
	Label       string                 `json:"label"`
	Type        string                 `json:"type"`
	Group       string                 `json:"group,omitempty"`
	Color       string                 `json:"color,omitempty"`
	Size        int                    `json:"size,omitempty"`
	Shape       string                 `json:"shape,omitempty"`
	RiskLevel   RiskLevel              `json:"risk_level,omitempty"`
	Criticality CriticalityLevel       `json:"criticality,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// VisualEdge represents an edge in the visualization
type VisualEdge struct {
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Label       string                 `json:"label,omitempty"`
	Type        string                 `json:"type"`
	Weight      float64                `json:"weight,omitempty"`
	Color       string                 `json:"color,omitempty"`
	Style       string                 `json:"style,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// VisualGroup represents a group in the visualization
type VisualGroup struct {
	ID          string                 `json:"id"`
	Label       string                 `json:"label"`
	Type        string                 `json:"type"`
	Color       string                 `json:"color,omitempty"`
	Nodes       []string               `json:"nodes"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NewDependencyVisualizer creates a new dependency visualizer
func NewDependencyVisualizer(analyzer *DependencyAnalyzer, auditLogger *telemetry.AuditLogger) *DependencyVisualizer {
	return &DependencyVisualizer{
		analyzer:    analyzer,
		auditLogger: auditLogger,
	}
}

// GenerateProcessGraph generates a visualization of the process dependency graph
func (dv *DependencyVisualizer) GenerateProcessGraph(config VisualizationConfig) (*GraphVisualization, error) {
	processGraph := dv.analyzer.GetProcessGraph()
	
	visualization := &GraphVisualization{
		Type:        "process_dependency",
		Title:       "Process Dependency Graph",
		Description: "Shows dependencies between processes in the system",
		Nodes:       []VisualNode{},
		Edges:       []VisualEdge{},
		Groups:      []VisualGroup{},
		Metadata:    make(map[string]interface{}),
		GeneratedAt: time.Now(),
	}
	
	// Generate nodes
	nodeCount := 0
	for pid, node := range processGraph.Nodes {
		if config.MaxNodes > 0 && nodeCount >= config.MaxNodes {
			break
		}
		
		// Apply filters
		if !dv.shouldIncludeNode(node.RiskLevel, node.Type, config) {
			continue
		}
		
		visualNode := VisualNode{
			ID:          fmt.Sprintf("process_%d", pid),
			Label:       fmt.Sprintf("%s (PID %d)", node.Name, pid),
			Type:        node.Type,
			Group:       dv.getNodeGroup(node, config.GroupBy),
			Color:       dv.getNodeColor(node.RiskLevel, node.Criticality),
			Size:        dv.getNodeSize(node.Criticality),
			Shape:       dv.getNodeShape(node.Type),
			RiskLevel:   node.RiskLevel,
			Criticality: node.Criticality,
			Metadata:    make(map[string]interface{}),
		}
		
		if config.IncludeMetadata {
			visualNode.Metadata = node.Metadata
		}
		
		visualization.Nodes = append(visualization.Nodes, visualNode)
		nodeCount++
	}
	
	// Generate edges
	edgeCount := 0
	for edgeKey, edge := range processGraph.Edges {
		if config.MaxEdges > 0 && edgeCount >= config.MaxEdges {
			break
		}
		
		visualEdge := VisualEdge{
			Source:   fmt.Sprintf("process_%d", edge.Source),
			Target:   fmt.Sprintf("process_%d", edge.Target),
			Label:    string(edge.Type),
			Type:     string(edge.Type),
			Weight:   edge.Weight,
			Color:    dv.getEdgeColor(edge.Type),
			Style:    dv.getEdgeStyle(edge.Type),
			Metadata: make(map[string]interface{}),
		}
		
		if config.IncludeMetadata {
			visualEdge.Metadata = edge.Metadata
		}
		
		visualization.Edges = append(visualization.Edges, visualEdge)
		edgeCount++
	}
	
	// Generate groups if requested
	if config.GroupBy != "" {
		visualization.Groups = dv.generateGroups(visualization.Nodes, config.GroupBy)
	}
	
	// Add metadata
	visualization.Metadata["total_nodes"] = len(processGraph.Nodes)
	visualization.Metadata["total_edges"] = len(processGraph.Edges)
	visualization.Metadata["filtered_nodes"] = len(visualization.Nodes)
	visualization.Metadata["filtered_edges"] = len(visualization.Edges)
	
	// Log visualization generation
	dv.auditLogger.LogCustomEvent(telemetry.EventTypeAnalysisEvent, telemetry.SeverityInfo,
		"Process dependency graph visualization generated",
		map[string]interface{}{
			"format":         config.Format,
			"total_nodes":    len(processGraph.Nodes),
			"filtered_nodes": len(visualization.Nodes),
			"total_edges":    len(processGraph.Edges),
			"filtered_edges": len(visualization.Edges),
		})
	
	return visualization, nil
}

// GenerateServiceGraph generates a visualization of the service dependency graph
func (dv *DependencyVisualizer) GenerateServiceGraph(config VisualizationConfig) (*GraphVisualization, error) {
	serviceGraph := dv.analyzer.GetServiceGraph()
	
	visualization := &GraphVisualization{
		Type:        "service_dependency",
		Title:       "Service Dependency Graph",
		Description: "Shows dependencies between services in the system",
		Nodes:       []VisualNode{},
		Edges:       []VisualEdge{},
		Groups:      []VisualGroup{},
		Metadata:    make(map[string]interface{}),
		GeneratedAt: time.Now(),
	}
	
	// Generate nodes
	nodeCount := 0
	for id, node := range serviceGraph.Nodes {
		if config.MaxNodes > 0 && nodeCount >= config.MaxNodes {
			break
		}
		
		// Apply filters
		if !dv.shouldIncludeNode(node.RiskLevel, node.Type, config) {
			continue
		}
		
		visualNode := VisualNode{
			ID:          id,
			Label:       fmt.Sprintf("%s (%s:%d)", node.Name, node.Address, node.Port),
			Type:        node.Type,
			Group:       dv.getServiceNodeGroup(node, config.GroupBy),
			Color:       dv.getServiceNodeColor(node.HealthStatus, node.RiskLevel),
			Size:        dv.getNodeSize(node.Criticality),
			Shape:       dv.getNodeShape(node.Type),
			RiskLevel:   node.RiskLevel,
			Criticality: node.Criticality,
			Metadata:    make(map[string]interface{}),
		}
		
		if config.IncludeMetadata {
			visualNode.Metadata = node.Metadata
		}
		
		visualization.Nodes = append(visualization.Nodes, visualNode)
		nodeCount++
	}
	
	// Generate edges
	edgeCount := 0
	for edgeKey, edge := range serviceGraph.Edges {
		if config.MaxEdges > 0 && edgeCount >= config.MaxEdges {
			break
		}
		
		visualEdge := VisualEdge{
			Source:   edge.Source,
			Target:   edge.Target,
			Label:    fmt.Sprintf("%.2f%%", edge.SuccessRate*100),
			Type:     string(edge.Type),
			Weight:   edge.Weight,
			Color:    dv.getServiceEdgeColor(edge.SuccessRate),
			Style:    dv.getEdgeStyle(edge.Type),
			Metadata: make(map[string]interface{}),
		}
		
		if config.IncludeMetadata {
			visualEdge.Metadata = edge.Metadata
		}
		
		visualization.Edges = append(visualization.Edges, visualEdge)
		edgeCount++
	}
	
	// Generate groups if requested
	if config.GroupBy != "" {
		visualization.Groups = dv.generateGroups(visualization.Nodes, config.GroupBy)
	}
	
	// Add metadata
	visualization.Metadata["total_nodes"] = len(serviceGraph.Nodes)
	visualization.Metadata["total_edges"] = len(serviceGraph.Edges)
	visualization.Metadata["filtered_nodes"] = len(visualization.Nodes)
	visualization.Metadata["filtered_edges"] = len(visualization.Edges)
	
	// Log visualization generation
	dv.auditLogger.LogCustomEvent(telemetry.EventTypeAnalysisEvent, telemetry.SeverityInfo,
		"Service dependency graph visualization generated",
		map[string]interface{}{
			"format":         config.Format,
			"total_nodes":    len(serviceGraph.Nodes),
			"filtered_nodes": len(visualization.Nodes),
			"total_edges":    len(serviceGraph.Edges),
			"filtered_edges": len(visualization.Edges),
		})
	
	return visualization, nil
}

// GenerateFileAccessGraph generates a visualization of the file access graph
func (dv *DependencyVisualizer) GenerateFileAccessGraph(config VisualizationConfig) (*GraphVisualization, error) {
	fileGraph := dv.analyzer.GetFileAccessGraph()
	
	visualization := &GraphVisualization{
		Type:        "file_access",
		Title:       "File Access Graph",
		Description: "Shows file access patterns by processes",
		Nodes:       []VisualNode{},
		Edges:       []VisualEdge{},
		Groups:      []VisualGroup{},
		Metadata:    make(map[string]interface{}),
		GeneratedAt: time.Now(),
	}
	
	// Generate nodes
	nodeCount := 0
	for path, node := range fileGraph.Nodes {
		if config.MaxNodes > 0 && nodeCount >= config.MaxNodes {
			break
		}
		
		// Apply filters
		if !dv.shouldIncludeNode(node.RiskLevel, node.Type, config) {
			continue
		}
		
		visualNode := VisualNode{
			ID:          fmt.Sprintf("file_%s", strings.ReplaceAll(path, "/", "_")),
			Label:       path,
			Type:        node.Type,
			Group:       dv.getFileNodeGroup(node, config.GroupBy),
			Color:       dv.getNodeColor(node.RiskLevel, node.Criticality),
			Size:        dv.getFileNodeSize(node.AccessCount),
			Shape:       dv.getNodeShape(node.Type),
			RiskLevel:   node.RiskLevel,
			Criticality: node.Criticality,
			Metadata:    make(map[string]interface{}),
		}
		
		if config.IncludeMetadata {
			visualNode.Metadata = node.Metadata
		}
		
		visualization.Nodes = append(visualization.Nodes, visualNode)
		nodeCount++
	}
	
	// Generate edges
	edgeCount := 0
	for edgeKey, edge := range fileGraph.Edges {
		if config.MaxEdges > 0 && edgeCount >= config.MaxEdges {
			break
		}
		
		visualEdge := VisualEdge{
			Source:   fmt.Sprintf("process_%d", edge.ProcessID),
			Target:   fmt.Sprintf("file_%s", strings.ReplaceAll(edge.FilePath, "/", "_")),
			Label:    edge.AccessType,
			Type:     "file_access",
			Weight:   float64(edge.Frequency),
			Color:    dv.getFileAccessEdgeColor(edge.AccessType),
			Style:    dv.getEdgeStyle("file_access"),
			Metadata: make(map[string]interface{}),
		}
		
		if config.IncludeMetadata {
			visualEdge.Metadata = edge.Metadata
		}
		
		visualization.Edges = append(visualization.Edges, visualEdge)
		edgeCount++
	}
	
	// Generate groups if requested
	if config.GroupBy != "" {
		visualization.Groups = dv.generateGroups(visualization.Nodes, config.GroupBy)
	}
	
	// Add metadata
	visualization.Metadata["total_nodes"] = len(fileGraph.Nodes)
	visualization.Metadata["total_edges"] = len(fileGraph.Edges)
	visualization.Metadata["filtered_nodes"] = len(visualization.Nodes)
	visualization.Metadata["filtered_edges"] = len(visualization.Edges)
	
	// Log visualization generation
	dv.auditLogger.LogCustomEvent(telemetry.EventTypeAnalysisEvent, telemetry.SeverityInfo,
		"File access graph visualization generated",
		map[string]interface{}{
			"format":         config.Format,
			"total_nodes":    len(fileGraph.Nodes),
			"filtered_nodes": len(visualization.Nodes),
			"total_edges":    len(fileGraph.Edges),
			"filtered_edges": len(visualization.Edges),
		})
	
	return visualization, nil
}

// GenerateNetworkGraph generates a visualization of the network dependency graph
func (dv *DependencyVisualizer) GenerateNetworkGraph(config VisualizationConfig) (*GraphVisualization, error) {
	networkGraph := dv.analyzer.GetNetworkGraph()
	
	visualization := &GraphVisualization{
		Type:        "network_dependency",
		Title:       "Network Dependency Graph",
		Description: "Shows network connections and dependencies",
		Nodes:       []VisualNode{},
		Edges:       []VisualEdge{},
		Groups:      []VisualGroup{},
		Metadata:    make(map[string]interface{}),
		GeneratedAt: time.Now(),
	}
	
	// Generate nodes
	nodeCount := 0
	for addr, node := range networkGraph.Nodes {
		if config.MaxNodes > 0 && nodeCount >= config.MaxNodes {
			break
		}
		
		// Apply filters
		if !dv.shouldIncludeNode(node.RiskLevel, node.Type, config) {
			continue
		}
		
		visualNode := VisualNode{
			ID:          addr,
			Label:       fmt.Sprintf("%s:%d", node.Address, node.Port),
			Type:        node.Type,
			Group:       dv.getNetworkNodeGroup(node, config.GroupBy),
			Color:       dv.getNodeColor(node.RiskLevel, node.Criticality),
			Size:        dv.getNodeSize(node.Criticality),
			Shape:       dv.getNodeShape(node.Type),
			RiskLevel:   node.RiskLevel,
			Criticality: node.Criticality,
			Metadata:    make(map[string]interface{}),
		}
		
		if config.IncludeMetadata {
			visualNode.Metadata = node.Metadata
		}
		
		visualization.Nodes = append(visualization.Nodes, visualNode)
		nodeCount++
	}
	
	// Generate edges
	edgeCount := 0
	for edgeKey, edge := range networkGraph.Edges {
		if config.MaxEdges > 0 && edgeCount >= config.MaxEdges {
			break
		}
		
		visualEdge := VisualEdge{
			Source:   edge.Source,
			Target:   edge.Target,
			Label:    fmt.Sprintf("%s (%d bytes)", edge.Protocol, edge.Bytes),
			Type:     edge.Protocol,
			Weight:   float64(edge.Bytes),
			Color:    dv.getNetworkEdgeColor(edge.Protocol),
			Style:    dv.getEdgeStyle("network"),
			Metadata: make(map[string]interface{}),
		}
		
		if config.IncludeMetadata {
			visualEdge.Metadata = edge.Metadata
		}
		
		visualization.Edges = append(visualization.Edges, visualEdge)
		edgeCount++
	}
	
	// Generate groups if requested
	if config.GroupBy != "" {
		visualization.Groups = dv.generateGroups(visualization.Nodes, config.GroupBy)
	}
	
	// Add metadata
	visualization.Metadata["total_nodes"] = len(networkGraph.Nodes)
	visualization.Metadata["total_edges"] = len(networkGraph.Edges)
	visualization.Metadata["filtered_nodes"] = len(visualization.Nodes)
	visualization.Metadata["filtered_edges"] = len(visualization.Edges)
	
	// Log visualization generation
	dv.auditLogger.LogCustomEvent(telemetry.EventTypeAnalysisEvent, telemetry.SeverityInfo,
		"Network dependency graph visualization generated",
		map[string]interface{}{
			"format":         config.Format,
			"total_nodes":    len(networkGraph.Nodes),
			"filtered_nodes": len(visualization.Nodes),
			"total_edges":    len(networkGraph.Edges),
			"filtered_edges": len(visualization.Edges),
		})
	
	return visualization, nil
}

// ExportVisualization exports a visualization in the specified format
func (dv *DependencyVisualizer) ExportVisualization(visualization *GraphVisualization, format string) (string, error) {
	switch strings.ToLower(format) {
	case "json":
		return dv.exportJSON(visualization)
	case "dot":
		return dv.exportDOT(visualization)
	case "mermaid":
		return dv.exportMermaid(visualization)
	case "text":
		return dv.exportText(visualization)
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

// Helper methods for visualization
func (dv *DependencyVisualizer) shouldIncludeNode(riskLevel RiskLevel, nodeType string, config VisualizationConfig) bool {
	// Check risk level filter
	if len(config.FilterByRisk) > 0 {
		found := false
		for _, risk := range config.FilterByRisk {
			if risk == riskLevel {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check type filter
	if len(config.FilterByType) > 0 {
		found := false
		for _, t := range config.FilterByType {
			if t == nodeType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	return true
}

func (dv *DependencyVisualizer) getNodeGroup(node interface{}, groupBy string) string {
	switch groupBy {
	case "namespace":
		if processNode, ok := node.(*ProcessNode); ok {
			return processNode.Namespace
		}
	case "type":
		if processNode, ok := node.(*ProcessNode); ok {
			return processNode.Type
		}
	case "risk_level":
		if processNode, ok := node.(*ProcessNode); ok {
			return string(processNode.RiskLevel)
		}
	}
	return "default"
}

func (dv *DependencyVisualizer) getServiceNodeGroup(node *ServiceNode, groupBy string) string {
	switch groupBy {
	case "namespace":
		return node.Namespace
	case "type":
		return node.Type
	case "risk_level":
		return string(node.RiskLevel)
	case "environment":
		return node.Environment
	}
	return "default"
}

func (dv *DependencyVisualizer) getFileNodeGroup(node *FileNode, groupBy string) string {
	switch groupBy {
	case "type":
		return node.Type
	case "risk_level":
		return string(node.RiskLevel)
	}
	return "default"
}

func (dv *DependencyVisualizer) getNetworkNodeGroup(node *NetworkNode, groupBy string) string {
	switch groupBy {
	case "type":
		return node.Type
	case "risk_level":
		return string(node.RiskLevel)
	}
	return "default"
}

func (dv *DependencyVisualizer) getNodeColor(riskLevel RiskLevel, criticality CriticalityLevel) string {
	if riskLevel == RiskCritical || criticality == CriticalityCritical {
		return "#ff0000" // Red
	} else if riskLevel == RiskHigh || criticality == CriticalityHigh {
		return "#ff8800" // Orange
	} else if riskLevel == RiskMedium || criticality == CriticalityMedium {
		return "#ffaa00" // Yellow
	}
	return "#00aa00" // Green
}

func (dv *DependencyVisualizer) getServiceNodeColor(healthStatus string, riskLevel RiskLevel) string {
	if healthStatus == "unhealthy" {
		return "#ff0000" // Red
	} else if healthStatus == "degraded" {
		return "#ff8800" // Orange
	} else if riskLevel == RiskHigh {
		return "#ffaa00" // Yellow
	}
	return "#00aa00" // Green
}

func (dv *DependencyVisualizer) getNodeSize(criticality CriticalityLevel) int {
	switch criticality {
	case CriticalityCritical:
		return 20
	case CriticalityHigh:
		return 15
	case CriticalityMedium:
		return 10
	default:
		return 5
	}
}

func (dv *DependencyVisualizer) getFileNodeSize(accessCount int) int {
	if accessCount > 100 {
		return 20
	} else if accessCount > 50 {
		return 15
	} else if accessCount > 10 {
		return 10
	}
	return 5
}

func (dv *DependencyVisualizer) getNodeShape(nodeType string) string {
	switch nodeType {
	case "database":
		return "cylinder"
	case "webserver":
		return "rect"
	case "cache":
		return "diamond"
	case "system":
		return "star"
	default:
		return "circle"
	}
}

func (dv *DependencyVisualizer) getEdgeColor(edgeType DependencyType) string {
	switch edgeType {
	case DepTypeParentChild:
		return "#0000ff" // Blue
	case DepTypeCommunication:
		return "#00ff00" // Green
	case DepTypeFileAccess:
		return "#ff00ff" // Magenta
	case DepTypeNetwork:
		return "#00ffff" // Cyan
	case DepTypeService:
		return "#ffff00" // Yellow
	default:
		return "#888888" // Gray
	}
}

func (dv *DependencyVisualizer) getServiceEdgeColor(successRate float64) string {
	if successRate > 0.9 {
		return "#00aa00" // Green
	} else if successRate > 0.7 {
		return "#ffaa00" // Yellow
	} else if successRate > 0.5 {
		return "#ff8800" // Orange
	}
	return "#ff0000" // Red
}

func (dv *DependencyVisualizer) getFileAccessEdgeColor(accessType string) string {
	switch accessType {
	case "read":
		return "#00aa00" // Green
	case "write":
		return "#ff0000" // Red
	case "read_write":
		return "#ff8800" // Orange
	default:
		return "#888888" // Gray
	}
}

func (dv *DependencyVisualizer) getNetworkEdgeColor(protocol string) string {
	switch protocol {
	case "tcp":
		return "#0000ff" // Blue
	case "udp":
		return "#00ff00" // Green
	case "icmp":
		return "#ff00ff" // Magenta
	default:
		return "#888888" // Gray
	}
}

func (dv *DependencyVisualizer) getEdgeStyle(edgeType interface{}) string {
	switch edgeType {
	case DepTypeParentChild:
		return "solid"
	case DepTypeCommunication:
		return "dashed"
	case DepTypeFileAccess:
		return "dotted"
	case DepTypeNetwork:
		return "solid"
	case DepTypeService:
		return "dashed"
	default:
		return "solid"
	}
}

func (dv *DependencyVisualizer) generateGroups(nodes []VisualNode, groupBy string) []VisualGroup {
	groupMap := make(map[string][]string)
	
	for _, node := range nodes {
		group := node.Group
		if group == "" {
			group = "default"
		}
		groupMap[group] = append(groupMap[group], node.ID)
	}
	
	var groups []VisualGroup
	for groupName, nodeIDs := range groupMap {
		group := VisualGroup{
			ID:       groupName,
			Label:    groupName,
			Type:     groupBy,
			Color:    dv.getGroupColor(groupName),
			Nodes:    nodeIDs,
			Metadata: make(map[string]interface{}),
		}
		groups = append(groups, group)
	}
	
	return groups
}

func (dv *DependencyVisualizer) getGroupColor(groupName string) string {
	// Simple hash-based color assignment
	hash := 0
	for _, c := range groupName {
		hash = hash*31 + int(c)
	}
	colors := []string{"#ff6b6b", "#4ecdc4", "#45b7d1", "#96ceb4", "#feca57", "#ff9ff3", "#54a0ff"}
	return colors[hash%len(colors)]
}

// Export methods
func (dv *DependencyVisualizer) exportJSON(visualization *GraphVisualization) (string, error) {
	data, err := json.MarshalIndent(visualization, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(data), nil
}

func (dv *DependencyVisualizer) exportDOT(visualization *GraphVisualization) (string, error) {
	var builder strings.Builder
	
	builder.WriteString(fmt.Sprintf("digraph %s {\n", strings.ReplaceAll(visualization.Title, " ", "_")))
	builder.WriteString("  rankdir=LR;\n")
	builder.WriteString("  node [shape=circle];\n")
	
	// Add nodes
	for _, node := range visualization.Nodes {
		attrs := []string{fmt.Sprintf("label=\"%s\"", node.Label)}
		if node.Color != "" {
			attrs = append(attrs, fmt.Sprintf("color=\"%s\"", node.Color))
		}
		if node.Shape != "" {
			attrs = append(attrs, fmt.Sprintf("shape=%s", node.Shape))
		}
		builder.WriteString(fmt.Sprintf("  %s [%s];\n", node.ID, strings.Join(attrs, ", ")))
	}
	
	// Add edges
	for _, edge := range visualization.Edges {
		attrs := []string{}
		if edge.Label != "" {
			attrs = append(attrs, fmt.Sprintf("label=\"%s\"", edge.Label))
		}
		if edge.Color != "" {
			attrs = append(attrs, fmt.Sprintf("color=\"%s\"", edge.Color))
		}
		if edge.Style != "" {
			attrs = append(attrs, fmt.Sprintf("style=%s", edge.Style))
		}
		builder.WriteString(fmt.Sprintf("  %s -> %s", edge.Source, edge.Target))
		if len(attrs) > 0 {
			builder.WriteString(fmt.Sprintf(" [%s]", strings.Join(attrs, ", ")))
		}
		builder.WriteString(";\n")
	}
	
	builder.WriteString("}\n")
	return builder.String(), nil
}

func (dv *DependencyVisualizer) exportMermaid(visualization *GraphVisualization) (string, error) {
	var builder strings.Builder
	
	builder.WriteString("graph TD\n")
	
	// Add nodes
	for _, node := range visualization.Nodes {
		builder.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", node.ID, node.Label))
	}
	
	// Add edges
	for _, edge := range visualization.Edges {
		builder.WriteString(fmt.Sprintf("  %s --> %s\n", edge.Source, edge.Target))
	}
	
	return builder.String(), nil
}

func (dv *DependencyVisualizer) exportText(visualization *GraphVisualization) (string, error) {
	var builder strings.Builder
	
	builder.WriteString(fmt.Sprintf("%s\n", visualization.Title))
	builder.WriteString(fmt.Sprintf("%s\n\n", visualization.Description))
	
	// Add nodes
	builder.WriteString("Nodes:\n")
	for _, node := range visualization.Nodes {
		builder.WriteString(fmt.Sprintf("  - %s (%s) [%s, %s]\n", 
			node.Label, node.ID, node.Type, node.RiskLevel))
	}
	
	// Add edges
	builder.WriteString("\nEdges:\n")
	for _, edge := range visualization.Edges {
		builder.WriteString(fmt.Sprintf("  - %s -> %s (%s)\n", 
			edge.Source, edge.Target, edge.Type))
	}
	
	// Add metadata
	builder.WriteString(fmt.Sprintf("\nMetadata:\n"))
	for key, value := range visualization.Metadata {
		builder.WriteString(fmt.Sprintf("  - %s: %v\n", key, value))
	}
	
	return builder.String(), nil
}
