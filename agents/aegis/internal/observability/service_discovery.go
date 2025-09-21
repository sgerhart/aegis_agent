package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
)

// ServiceDiscovery manages service discovery and dependency tracking
type ServiceDiscovery struct {
	services        map[string]*Service
	dependencies    map[string][]*ServiceDependency
	healthChecks    map[string]*HealthCheck
	auditLogger     *telemetry.AuditLogger
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
	running         bool
	checkInterval   time.Duration
}

// Service represents a discovered service
type Service struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Type            string                 `json:"type"` // http, tcp, udp, grpc, etc.
	Address         string                 `json:"address"`
	Port            int                    `json:"port"`
	Protocol        string                 `json:"protocol"`
	Namespace       string                 `json:"namespace"`
	Environment     string                 `json:"environment"`
	Version         string                 `json:"version"`
	HealthEndpoint  string                 `json:"health_endpoint"`
	Tags            map[string]string      `json:"tags"`
	Metadata        map[string]interface{} `json:"metadata"`
	LastSeen        time.Time              `json:"last_seen"`
	HealthStatus    HealthStatus           `json:"health_status"`
	ProcessID       uint32                 `json:"process_id,omitempty"`
	ContainerID     string                 `json:"container_id,omitempty"`
	PodName         string                 `json:"pod_name,omitempty"`
	NodeName        string                 `json:"node_name,omitempty"`
}

// ServiceDependency represents a dependency between services
type ServiceDependency struct {
	SourceServiceID string            `json:"source_service_id"`
	TargetServiceID string            `json:"target_service_id"`
	Type            DependencyType    `json:"type"` // direct, indirect, optional, required
	Weight          int               `json:"weight"`
	Latency         time.Duration     `json:"latency"`
	SuccessRate     float64           `json:"success_rate"`
	LastCheck       time.Time         `json:"last_check"`
	Metadata        map[string]string `json:"metadata"`
}

// HealthCheck represents a health check configuration
type HealthCheck struct {
	ServiceID       string        `json:"service_id"`
	Endpoint        string        `json:"endpoint"`
	Interval        time.Duration `json:"interval"`
	Timeout         time.Duration `json:"timeout"`
	Retries         int           `json:"retries"`
	SuccessThreshold int          `json:"success_threshold"`
	FailureThreshold int          `json:"failure_threshold"`
	CurrentFailures  int          `json:"current_failures"`
	CurrentSuccesses int          `json:"current_successes"`
	LastCheck        time.Time    `json:"last_check"`
	Status           HealthStatus `json:"status"`
}

// HealthStatus represents the health status of a service
type HealthStatus string

const (
	HealthUnknown    HealthStatus = "unknown"
	HealthHealthy    HealthStatus = "healthy"
	HealthUnhealthy  HealthStatus = "unhealthy"
	HealthDegraded   HealthStatus = "degraded"
	HealthStarting   HealthStatus = "starting"
	HealthStopping   HealthStatus = "stopping"
)

// DependencyType represents the type of service dependency
type DependencyType string

const (
	DependencyDirect   DependencyType = "direct"
	DependencyIndirect DependencyType = "indirect"
	DependencyOptional DependencyType = "optional"
	DependencyRequired DependencyType = "required"
)

// ServiceDiscoveryConfig holds configuration for service discovery
type ServiceDiscoveryConfig struct {
	CheckInterval    time.Duration `json:"check_interval"`
	DefaultTimeout   time.Duration `json:"default_timeout"`
	DefaultRetries   int           `json:"default_retries"`
	MaxServices      int           `json:"max_services"`
	EnableKubernetes bool          `json:"enable_kubernetes"`
	EnableDocker     bool          `json:"enable_docker"`
	EnableStatic     bool          `json:"enable_static"`
}

// NewServiceDiscovery creates a new service discovery instance
func NewServiceDiscovery(auditLogger *telemetry.AuditLogger, config ServiceDiscoveryConfig) *ServiceDiscovery {
	ctx, cancel := context.WithCancel(context.Background())
	
	sd := &ServiceDiscovery{
		services:      make(map[string]*Service),
		dependencies:  make(map[string][]*ServiceDependency),
		healthChecks:  make(map[string]*HealthCheck),
		auditLogger:   auditLogger,
		ctx:           ctx,
		cancel:        cancel,
		checkInterval: config.CheckInterval,
	}
	
	// Set default values
	if sd.checkInterval == 0 {
		sd.checkInterval = 30 * time.Second
	}
	
	log.Printf("[service_discovery] Service discovery initialized")
	return sd
}

// Start starts the service discovery
func (sd *ServiceDiscovery) Start() error {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	
	if sd.running {
		return fmt.Errorf("service discovery already running")
	}
	
	sd.running = true
	
	// Start discovery goroutines
	go sd.discoverServices()
	go sd.performHealthChecks()
	go sd.analyzeDependencies()
	
	log.Printf("[service_discovery] Service discovery started")
	
	// Log startup event
	sd.auditLogger.LogSystemEvent("service_discovery_start", "Service discovery started", map[string]interface{}{
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"check_interval":  sd.checkInterval.String(),
	})
	
	return nil
}

// Stop stops the service discovery
func (sd *ServiceDiscovery) Stop() error {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	
	if !sd.running {
		return fmt.Errorf("service discovery not running")
	}
	
	sd.cancel()
	sd.running = false
	
	log.Printf("[service_discovery] Service discovery stopped")
	
	// Log shutdown event
	sd.auditLogger.LogSystemEvent("service_discovery_stop", "Service discovery stopped", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	
	return nil
}

// discoverServices continuously discovers services
func (sd *ServiceDiscovery) discoverServices() {
	ticker := time.NewTicker(sd.checkInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sd.performServiceDiscovery()
		case <-sd.ctx.Done():
			return
		}
	}
}

// performServiceDiscovery performs the actual service discovery
func (sd *ServiceDiscovery) performServiceDiscovery() {
	// Discover services from different sources
	sd.discoverFromNetworkScans()
	sd.discoverFromProcessAnalysis()
	sd.discoverFromKubernetes()
	sd.discoverFromDocker()
	sd.discoverFromStaticConfig()
	
	// Clean up old services
	sd.cleanupOldServices()
}

// discoverFromNetworkScans discovers services by scanning network ports
func (sd *ServiceDiscovery) discoverFromNetworkScans() {
	// Common ports to scan
	commonPorts := []int{80, 443, 8080, 8443, 3000, 5000, 8000, 9000, 3306, 5432, 6379, 27017}
	
	for _, port := range commonPorts {
		// Scan localhost for now (in production, would scan network ranges)
		address := fmt.Sprintf("localhost:%d", port)
		if sd.isServiceListening(address) {
			service := &Service{
				ID:           fmt.Sprintf("network_scan_%d", port),
				Name:         fmt.Sprintf("service_on_port_%d", port),
				Type:         "unknown",
				Address:      "localhost",
				Port:         port,
				Protocol:     "tcp",
				Namespace:    "default",
				Environment:  "production",
				HealthStatus: HealthUnknown,
				LastSeen:     time.Now(),
				Tags:         make(map[string]string),
				Metadata:     make(map[string]interface{}),
			}
			
			// Try to identify service type
			service.Type = sd.identifyServiceType(port)
			
			sd.addService(service)
		}
	}
}

// discoverFromProcessAnalysis discovers services from running processes
func (sd *ServiceDiscovery) discoverFromProcessAnalysis() {
	// This would integrate with the process monitor to identify services
	// For now, we'll add some common services
	
	commonServices := []Service{
		{
			ID:           "nginx_80",
			Name:         "nginx",
			Type:         "http",
			Address:      "localhost",
			Port:         80,
			Protocol:     "tcp",
			Namespace:    "default",
			Environment:  "production",
			HealthStatus: HealthHealthy,
			LastSeen:     time.Now(),
			Tags:         map[string]string{"role": "webserver"},
			Metadata:     map[string]interface{}{"version": "1.20.1"},
		},
		{
			ID:           "postgres_5432",
			Name:         "postgresql",
			Type:         "database",
			Address:      "localhost",
			Port:         5432,
			Protocol:     "tcp",
			Namespace:    "default",
			Environment:  "production",
			HealthStatus: HealthHealthy,
			LastSeen:     time.Now(),
			Tags:         map[string]string{"role": "database"},
			Metadata:     map[string]interface{}{"version": "13.4"},
		},
	}
	
	for _, service := range commonServices {
		sd.addService(&service)
	}
}

// discoverFromKubernetes discovers services from Kubernetes
func (sd *ServiceDiscovery) discoverFromKubernetes() {
	// This would integrate with Kubernetes API to discover services
	// For now, we'll simulate some Kubernetes services
	
	k8sServices := []Service{
		{
			ID:           "k8s_webapp_8080",
			Name:         "webapp",
			Type:         "http",
			Address:      "10.0.0.10",
			Port:         8080,
			Protocol:     "tcp",
			Namespace:    "production",
			Environment:  "production",
			HealthStatus: HealthHealthy,
			LastSeen:     time.Now(),
			Tags:         map[string]string{"k8s": "true", "app": "webapp"},
			Metadata:     map[string]interface{}{"pod": "webapp-7d4b8c9f6-xyz12"},
			PodName:      "webapp-7d4b8c9f6-xyz12",
			NodeName:     "worker-1",
		},
		{
			ID:           "k8s_api_443",
			Name:         "api-server",
			Type:         "http",
			Address:      "10.0.0.5",
			Port:         443,
			Protocol:     "tcp",
			Namespace:    "kube-system",
			Environment:  "production",
			HealthStatus: HealthHealthy,
			LastSeen:     time.Now(),
			Tags:         map[string]string{"k8s": "true", "component": "api-server"},
			Metadata:     map[string]interface{}{"version": "1.21.0"},
		},
	}
	
	for _, service := range k8sServices {
		sd.addService(&service)
	}
}

// discoverFromDocker discovers services from Docker containers
func (sd *ServiceDiscovery) discoverFromDocker() {
	// This would integrate with Docker API to discover services
	// For now, we'll simulate some Docker services
	
	dockerServices := []Service{
		{
			ID:           "docker_redis_6379",
			Name:         "redis",
			Type:         "cache",
			Address:      "172.17.0.2",
			Port:         6379,
			Protocol:     "tcp",
			Namespace:    "docker",
			Environment:  "production",
			HealthStatus: HealthHealthy,
			LastSeen:     time.Now(),
			Tags:         map[string]string{"docker": "true", "role": "cache"},
			Metadata:     map[string]interface{}{"container": "redis-container"},
			ContainerID:  "abc123def456",
		},
	}
	
	for _, service := range dockerServices {
		sd.addService(&service)
	}
}

// discoverFromStaticConfig discovers services from static configuration
func (sd *ServiceDiscovery) discoverFromStaticConfig() {
	// This would read from configuration files
	// For now, we'll add some static services
	
	staticServices := []Service{
		{
			ID:           "static_monitoring_9090",
			Name:         "prometheus",
			Type:         "monitoring",
			Address:      "localhost",
			Port:         9090,
			Protocol:     "tcp",
			Namespace:    "monitoring",
			Environment:  "production",
			HealthStatus: HealthHealthy,
			LastSeen:     time.Now(),
			Tags:         map[string]string{"role": "monitoring"},
			Metadata:     map[string]interface{}{"version": "2.30.0"},
		},
	}
	
	for _, service := range staticServices {
		sd.addService(&service)
	}
}

// addService adds a service to the discovery
func (sd *ServiceDiscovery) addService(service *Service) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	
	// Check if service already exists
	if existing, exists := sd.services[service.ID]; exists {
		// Update existing service
		existing.LastSeen = time.Now()
		existing.HealthStatus = service.HealthStatus
		// Update other fields as needed
	} else {
		// Add new service
		sd.services[service.ID] = service
		
		// Log service discovery
		sd.auditLogger.LogCustomEvent(telemetry.EventTypeServiceEvent, telemetry.SeverityInfo,
			fmt.Sprintf("Service discovered: %s", service.Name),
			map[string]interface{}{
				"service_id":   service.ID,
				"service_name": service.Name,
				"service_type": service.Type,
				"address":      service.Address,
				"port":         service.Port,
				"namespace":    service.Namespace,
				"environment":  service.Environment,
			})
	}
}

// isServiceListening checks if a service is listening on the given address
func (sd *ServiceDiscovery) isServiceListening(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// identifyServiceType identifies the type of service based on port
func (sd *ServiceDiscovery) identifyServiceType(port int) string {
	portTypes := map[int]string{
		80:    "http",
		443:   "https",
		8080:  "http",
		8443:  "https",
		3000:  "http",
		5000:  "http",
		8000:  "http",
		9000:  "http",
		3306:  "mysql",
		5432:  "postgresql",
		6379:  "redis",
		27017: "mongodb",
		9090:  "prometheus",
	}
	
	if serviceType, exists := portTypes[port]; exists {
		return serviceType
	}
	return "unknown"
}

// performHealthChecks performs health checks on discovered services
func (sd *ServiceDiscovery) performHealthChecks() {
	ticker := time.NewTicker(sd.checkInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sd.checkAllServices()
		case <-sd.ctx.Done():
			return
		}
	}
}

// checkAllServices performs health checks on all services
func (sd *ServiceDiscovery) checkAllServices() {
	sd.mu.RLock()
	services := make([]*Service, 0, len(sd.services))
	for _, service := range sd.services {
		services = append(services, service)
	}
	sd.mu.RUnlock()
	
	for _, service := range services {
		go sd.checkServiceHealth(service)
	}
}

// checkServiceHealth performs a health check on a single service
func (sd *ServiceDiscovery) checkServiceHealth(service *Service) {
	start := time.Now()
	
	// Perform different types of health checks based on service type
	var healthy bool
	var err error
	
	switch service.Type {
	case "http", "https":
		healthy, err = sd.checkHTTPHealth(service)
	case "tcp":
		healthy, err = sd.checkTCPHealth(service)
	default:
		healthy, err = sd.checkGenericHealth(service)
	}
	
	latency := time.Since(start)
	
	sd.mu.Lock()
	defer sd.mu.Unlock()
	
	// Update service health status
	oldStatus := service.HealthStatus
	if healthy {
		service.HealthStatus = HealthHealthy
	} else {
		service.HealthStatus = HealthUnhealthy
	}
	
	// Log health check result if status changed
	if oldStatus != service.HealthStatus {
		sd.auditLogger.LogCustomEvent(telemetry.EventTypeHealthEvent, telemetry.SeverityInfo,
			fmt.Sprintf("Service health changed: %s -> %s", service.Name, service.HealthStatus),
			map[string]interface{}{
				"service_id":     service.ID,
				"service_name":   service.Name,
				"old_status":     oldStatus,
				"new_status":     service.HealthStatus,
				"latency_ms":     latency.Milliseconds(),
				"error":          err,
			})
	}
}

// checkHTTPHealth performs HTTP health check
func (sd *ServiceDiscovery) checkHTTPHealth(service *Service) (bool, error) {
	url := fmt.Sprintf("http://%s:%d%s", service.Address, service.Port, service.HealthEndpoint)
	if service.HealthEndpoint == "" {
		url = fmt.Sprintf("http://%s:%d/", service.Address, service.Port)
	}
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// checkTCPHealth performs TCP health check
func (sd *ServiceDiscovery) checkTCPHealth(service *Service) (bool, error) {
	address := fmt.Sprintf("%s:%d", service.Address, service.Port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	
	return true, nil
}

// checkGenericHealth performs generic health check
func (sd *ServiceDiscovery) checkGenericHealth(service *Service) (bool, error) {
	// For unknown service types, just check if port is open
	return sd.isServiceListening(fmt.Sprintf("%s:%d", service.Address, service.Port)), nil
}

// analyzeDependencies analyzes dependencies between services
func (sd *ServiceDiscovery) analyzeDependencies() {
	ticker := time.NewTicker(sd.checkInterval * 2) // Run less frequently
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sd.buildDependencyGraph()
		case <-sd.ctx.Done():
			return
		}
	}
}

// buildDependencyGraph builds the dependency graph between services
func (sd *ServiceDiscovery) buildDependencyGraph() {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	
	// Clear existing dependencies
	sd.dependencies = make(map[string][]*ServiceDependency)
	
	// Build dependencies based on service types and common patterns
	for _, service := range sd.services {
		deps := sd.findServiceDependencies(service)
		if len(deps) > 0 {
			sd.dependencies[service.ID] = deps
		}
	}
	
	// Log dependency analysis
	sd.auditLogger.LogCustomEvent(telemetry.EventTypeDependencyEvent, telemetry.SeverityInfo,
		"Service dependency graph updated",
		map[string]interface{}{
			"total_services":   len(sd.services),
			"total_dependencies": len(sd.dependencies),
		})
}

// findServiceDependencies finds dependencies for a service
func (sd *ServiceDiscovery) findServiceDependencies(service *Service) []*ServiceDependency {
	var dependencies []*ServiceDependency
	
	// Add common dependencies based on service type
	switch service.Type {
	case "http", "https":
		// Web services might depend on databases and caches
		dependencies = append(dependencies, sd.findDatabaseDependencies()...)
		dependencies = append(dependencies, sd.findCacheDependencies()...)
	case "database":
		// Databases don't typically have dependencies
		break
	case "cache":
		// Caches might depend on databases
		dependencies = append(dependencies, sd.findDatabaseDependencies()...)
	}
	
	return dependencies
}

// findDatabaseDependencies finds database service dependencies
func (sd *ServiceDiscovery) findDatabaseDependencies() []*ServiceDependency {
	var deps []*ServiceDependency
	
	for _, service := range sd.services {
		if service.Type == "database" || service.Type == "postgresql" || service.Type == "mysql" {
			dep := &ServiceDependency{
				SourceServiceID: "current_service",
				TargetServiceID: service.ID,
				Type:            DependencyRequired,
				Weight:          100,
				LastCheck:       time.Now(),
				Metadata:        map[string]string{"purpose": "data_storage"},
			}
			deps = append(deps, dep)
		}
	}
	
	return deps
}

// findCacheDependencies finds cache service dependencies
func (sd *ServiceDiscovery) findCacheDependencies() []*ServiceDependency {
	var deps []*ServiceDependency
	
	for _, service := range sd.services {
		if service.Type == "cache" || service.Type == "redis" {
			dep := &ServiceDependency{
				SourceServiceID: "current_service",
				TargetServiceID: service.ID,
				Type:            DependencyOptional,
				Weight:          50,
				LastCheck:       time.Now(),
				Metadata:        map[string]string{"purpose": "caching"},
			}
			deps = append(deps, dep)
		}
	}
	
	return deps
}

// cleanupOldServices removes services that haven't been seen recently
func (sd *ServiceDiscovery) cleanupOldServices() {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	
	cutoff := time.Now().Add(-10 * time.Minute) // Remove services not seen in 10 minutes
	
	for id, service := range sd.services {
		if service.LastSeen.Before(cutoff) {
			delete(sd.services, id)
			delete(sd.dependencies, id)
			delete(sd.healthChecks, id)
			
			// Log service removal
			sd.auditLogger.LogCustomEvent(telemetry.EventTypeServiceEvent, telemetry.SeverityInfo,
				fmt.Sprintf("Service removed: %s", service.Name),
				map[string]interface{}{
					"service_id":   service.ID,
					"service_name": service.Name,
					"last_seen":    service.LastSeen.Format(time.RFC3339),
				})
		}
	}
}

// GetServices returns all discovered services
func (sd *ServiceDiscovery) GetServices() map[string]*Service {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	
	services := make(map[string]*Service)
	for id, service := range sd.services {
		services[id] = service
	}
	
	return services
}

// GetServiceDependencies returns dependencies for a service
func (sd *ServiceDiscovery) GetServiceDependencies(serviceID string) []*ServiceDependency {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	
	return sd.dependencies[serviceID]
}

// GetServiceStatistics returns statistics about discovered services
func (sd *ServiceDiscovery) GetServiceStatistics() map[string]interface{} {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	
	stats := map[string]interface{}{
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"total_services":   len(sd.services),
		"total_dependencies": len(sd.dependencies),
		"health_status": map[string]int{
			"healthy":   0,
			"unhealthy": 0,
			"unknown":   0,
			"degraded":  0,
		},
		"service_types": make(map[string]int),
		"environments":  make(map[string]int),
	}
	
	// Count health statuses and types
	for _, service := range sd.services {
		// Health status count
		healthStats := stats["health_status"].(map[string]int)
		healthStats[string(service.HealthStatus)]++
		
		// Service type count
		typeStats := stats["service_types"].(map[string]int)
		typeStats[service.Type]++
		
		// Environment count
		envStats := stats["environments"].(map[string]int)
		envStats[service.Environment]++
	}
	
	return stats
}

// Close closes the service discovery
func (sd *ServiceDiscovery) Close() error {
	return sd.Stop()
}
