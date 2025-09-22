package modules

import (
	"context"
	"time"

	"agents/aegis/internal/telemetry"
	"agents/aegis/pkg/models"
)

// ModuleStatus represents the current status of a module
type ModuleStatus string

const (
	ModuleStatusStopped   ModuleStatus = "stopped"
	ModuleStatusStarting  ModuleStatus = "starting"
	ModuleStatusRunning   ModuleStatus = "running"
	ModuleStatusStopping  ModuleStatus = "stopping"
	ModuleStatusError     ModuleStatus = "error"
	ModuleStatusDisabled  ModuleStatus = "disabled"
)

// ModuleInfo provides metadata about a module
type ModuleInfo struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Author      string            `json:"author"`
	License     string            `json:"license"`
	Capabilities []string         `json:"capabilities"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ModuleConfig holds configuration for a module
type ModuleConfig struct {
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Settings    map[string]interface{} `json:"settings"`
	Environment map[string]string      `json:"environment"`
}

// ModuleInterface defines the interface that all modules must implement
type ModuleInterface interface {
	// Lifecycle methods
	Initialize(ctx context.Context, config ModuleConfig) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Cleanup(ctx context.Context) error

	// Status and info
	GetInfo() ModuleInfo
	GetStatus() ModuleStatus
	GetConfig() ModuleConfig

	// Communication
	HandleMessage(message interface{}) (interface{}, error)
	SendEvent(event telemetry.Event) error

	// Health and monitoring
	HealthCheck() error
	GetMetrics() map[string]interface{}
}

// ModuleManager manages the lifecycle of all modules
type ModuleManager interface {
	// Module management
	RegisterModule(module ModuleInterface) error
	UnregisterModule(moduleID string) error
	GetModule(moduleID string) (ModuleInterface, bool)
	GetAllModules() map[string]ModuleInterface

	// Lifecycle management
	StartModule(moduleID string) error
	StopModule(moduleID string) error
	RestartModule(moduleID string) error
	StartAllModules() error
	StopAllModules() error

	// Status and monitoring
	GetModuleStatus(moduleID string) (ModuleStatus, error)
	GetAllModuleStatuses() map[string]ModuleStatus
	GetModuleHealth(moduleID string) error
	GetAllModuleHealth() map[string]error

	// Communication
	SendMessageToModule(moduleID string, message interface{}) (interface{}, error)
	BroadcastMessage(message interface{}) map[string]interface{}
	SendEventToModule(moduleID string, event telemetry.Event) error
	BroadcastEvent(event telemetry.Event) error

	// Configuration
	UpdateModuleConfig(moduleID string, config ModuleConfig) error
	GetModuleConfig(moduleID string) (ModuleConfig, error)
	ReloadModuleConfig(moduleID string) error

	// Discovery and loading
	DiscoverModules() []string
	LoadModule(modulePath string) error
	UnloadModule(moduleID string) error
}

// EventHandler defines the interface for handling module events
type EventHandler interface {
	HandleModuleEvent(event ModuleEvent)
}

// ModuleEvent represents an event from a module
type ModuleEvent struct {
	ModuleID    string                 `json:"module_id"`
	Type        string                 `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Data        map[string]interface{} `json:"data"`
	Severity    string                 `json:"severity"`
}

// PolicyModuleInterface extends ModuleInterface for policy-related modules
type PolicyModuleInterface interface {
	ModuleInterface
	
	// Policy-specific methods
	ApplyPolicy(policy models.Policy) error
	RemovePolicy(policyID string) error
	ValidatePolicy(policy models.Policy) error
	GetPolicyStatus(policyID string) (string, error)
}

// ObservabilityModuleInterface extends ModuleInterface for observability modules
type ObservabilityModuleInterface interface {
	ModuleInterface
	
	// Observability-specific methods
	StartMonitoring() error
	StopMonitoring() error
	GetMetrics() map[string]interface{}
	ExportMetrics() ([]byte, error)
	SetLogLevel(level string) error
}

// CommunicationModuleInterface extends ModuleInterface for communication modules
type CommunicationModuleInterface interface {
	ModuleInterface
	
	// Communication-specific methods
	Connect(endpoint string) error
	Disconnect() error
	SendMessage(message interface{}) error
	ReceiveMessage() (interface{}, error)
	IsConnected() bool
}

// SecurityModuleInterface extends ModuleInterface for security modules
type SecurityModuleInterface interface {
	ModuleInterface
	
	// Security-specific methods
	Authenticate(credentials interface{}) error
	Authorize(action string, resource string) bool
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
	ValidateSignature(data []byte, signature []byte) bool
}

// ModuleFactory creates instances of modules
type ModuleFactory interface {
	CreateModule(moduleType string, config ModuleConfig) (ModuleInterface, error)
	GetSupportedTypes() []string
	RegisterFactory(moduleType string, factory func(ModuleConfig) (ModuleInterface, error)) error
}

// ModuleRegistry maintains a registry of available modules
type ModuleRegistry interface {
	Register(moduleType string, info ModuleInfo, factory ModuleFactory) error
	Unregister(moduleType string) error
	GetModuleInfo(moduleType string) (ModuleInfo, bool)
	GetAllModuleInfos() map[string]ModuleInfo
	GetAvailableTypes() []string
}

// ModuleLoader loads modules from various sources
type ModuleLoader interface {
	LoadFromPath(path string) (ModuleInterface, error)
	LoadFromConfig(config ModuleConfig) (ModuleInterface, error)
	LoadFromRegistry(moduleType string, config ModuleConfig) (ModuleInterface, error)
	Unload(moduleID string) error
}

// ModuleDependency represents a dependency between modules
type ModuleDependency struct {
	ModuleID     string `json:"module_id"`
	DependencyID string `json:"dependency_id"`
	Required     bool   `json:"required"`
	Version      string `json:"version"`
}

// DependencyManager manages module dependencies
type DependencyManager interface {
	AddDependency(moduleID string, dependency ModuleDependency) error
	RemoveDependency(moduleID string, dependencyID string) error
	GetDependencies(moduleID string) []ModuleDependency
	GetDependents(moduleID string) []string
	ResolveDependencies(moduleID string) ([]ModuleInterface, error)
	CheckDependencies(moduleID string) error
}
