package modules

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"agents/aegis/internal/telemetry"
)

// ModuleConfigManager manages module configurations
type ModuleConfigManager struct {
	configPath string
	configs    map[string]ModuleConfig
	logger     *telemetry.Logger
	mu         sync.RWMutex
}

// ModuleConfigFile represents the structure of a module configuration file
type ModuleConfigFile struct {
	Modules map[string]ModuleConfigEntry `json:"modules"`
	Global  GlobalConfig                 `json:"global"`
}

// ModuleConfigEntry represents a single module configuration entry
type ModuleConfigEntry struct {
	Type        string                 `json:"type"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Settings    map[string]interface{} `json:"settings"`
	Environment map[string]string      `json:"environment"`
	Dependencies []string              `json:"dependencies"`
}

// GlobalConfig represents global configuration for all modules
type GlobalConfig struct {
	LogLevel      string            `json:"log_level"`
	ModuleTimeout int               `json:"module_timeout"`
	MaxRetries    int               `json:"max_retries"`
	Environment   map[string]string `json:"environment"`
}

// NewModuleConfigManager creates a new module configuration manager
func NewModuleConfigManager(configPath string, logger *telemetry.Logger) *ModuleConfigManager {
	return &ModuleConfigManager{
		configPath: configPath,
		configs:    make(map[string]ModuleConfig),
		logger:     logger,
	}
}

// LoadConfig loads module configurations from file
func (mcm *ModuleConfigManager) LoadConfig() error {
	mcm.mu.Lock()
	defer mcm.mu.Unlock()

	// Check if config file exists
	if _, err := os.Stat(mcm.configPath); os.IsNotExist(err) {
		mcm.logger.LogWarn("config_warn", fmt.Sprintf("Module config file not found, creating default: %s", mcm.configPath), nil)
		return mcm.createDefaultConfig()
	}

	// Read config file
	data, err := ioutil.ReadFile(mcm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse config file
	var configFile ModuleConfigFile
	if err := json.Unmarshal(data, &configFile); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Convert to internal format
	mcm.configs = make(map[string]ModuleConfig)
	for moduleID, entry := range configFile.Modules {
		config := ModuleConfig{
			Enabled:     entry.Enabled,
			Priority:    entry.Priority,
			Settings:    entry.Settings,
			Environment: entry.Environment,
		}

		// Merge with global environment
		if config.Environment == nil {
			config.Environment = make(map[string]string)
		}
		for k, v := range configFile.Global.Environment {
			if _, exists := config.Environment[k]; !exists {
				config.Environment[k] = v
			}
		}

		mcm.configs[moduleID] = config
	}

	mcm.logger.LogInfo("config_info", fmt.Sprintf("Loaded %d module configurations", len(mcm.configs)), nil)
	return nil
}

// SaveConfig saves module configurations to file
func (mcm *ModuleConfigManager) SaveConfig() error {
	mcm.mu.RLock()
	defer mcm.mu.RUnlock()

	// Convert to file format
	configFile := ModuleConfigFile{
		Modules: make(map[string]ModuleConfigEntry),
		Global: GlobalConfig{
			LogLevel:    "info",
			ModuleTimeout: 30,
			MaxRetries:  3,
			Environment: make(map[string]string),
		},
	}

	for moduleID, config := range mcm.configs {
		entry := ModuleConfigEntry{
			Type:        "unknown", // This would need to be tracked separately
			Enabled:     config.Enabled,
			Priority:    config.Priority,
			Settings:    config.Settings,
			Environment: config.Environment,
		}
		configFile.Modules[moduleID] = entry
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(configFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(mcm.configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write to file
	if err := ioutil.WriteFile(mcm.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	mcm.logger.LogInfo("config_info", fmt.Sprintf("Saved module configurations to %s", mcm.configPath), nil)
	return nil
}

// GetModuleConfig gets configuration for a specific module
func (mcm *ModuleConfigManager) GetModuleConfig(moduleID string) (ModuleConfig, bool) {
	mcm.mu.RLock()
	defer mcm.mu.RUnlock()

	config, exists := mcm.configs[moduleID]
	return config, exists
}

// SetModuleConfig sets configuration for a specific module
func (mcm *ModuleConfigManager) SetModuleConfig(moduleID string, config ModuleConfig) {
	mcm.mu.Lock()
	defer mcm.mu.Unlock()

	mcm.configs[moduleID] = config
	mcm.logger.LogInfo("config_info", fmt.Sprintf("Updated configuration for module: %s", moduleID), nil)
}

// GetAllModuleConfigs returns all module configurations
func (mcm *ModuleConfigManager) GetAllModuleConfigs() map[string]ModuleConfig {
	mcm.mu.RLock()
	defer mcm.mu.RUnlock()

	configs := make(map[string]ModuleConfig)
	for k, v := range mcm.configs {
		configs[k] = v
	}
	return configs
}

// EnableModule enables a module
func (mcm *ModuleConfigManager) EnableModule(moduleID string) {
	mcm.mu.Lock()
	defer mcm.mu.Unlock()

	if config, exists := mcm.configs[moduleID]; exists {
		config.Enabled = true
		mcm.configs[moduleID] = config
		mcm.logger.LogInfo("config_info", fmt.Sprintf("Enabled module: %s", moduleID), nil)
	}
}

// DisableModule disables a module
func (mcm *ModuleConfigManager) DisableModule(moduleID string) {
	mcm.mu.Lock()
	defer mcm.mu.Unlock()

	if config, exists := mcm.configs[moduleID]; exists {
		config.Enabled = false
		mcm.configs[moduleID] = config
		mcm.logger.LogInfo("config_info", fmt.Sprintf("Disabled module: %s", moduleID), nil)
	}
}

// SetModuleSetting sets a specific setting for a module
func (mcm *ModuleConfigManager) SetModuleSetting(moduleID string, key string, value interface{}) {
	mcm.mu.Lock()
	defer mcm.mu.Unlock()

	config, exists := mcm.configs[moduleID]
	if !exists {
		config = ModuleConfig{
			Enabled:     true,
			Settings:    make(map[string]interface{}),
			Environment: make(map[string]string),
		}
	}

	if config.Settings == nil {
		config.Settings = make(map[string]interface{})
	}

	config.Settings[key] = value
	mcm.configs[moduleID] = config
	mcm.logger.LogInfo("config_info", fmt.Sprintf("Updated setting %s for module %s", key, moduleID), nil)
}

// GetModuleSetting gets a specific setting for a module
func (mcm *ModuleConfigManager) GetModuleSetting(moduleID string, key string) (interface{}, bool) {
	mcm.mu.RLock()
	defer mcm.mu.RUnlock()

	config, exists := mcm.configs[moduleID]
	if !exists {
		return nil, false
	}

	value, exists := config.Settings[key]
	return value, exists
}

// SetModuleEnvironment sets an environment variable for a module
func (mcm *ModuleConfigManager) SetModuleEnvironment(moduleID string, key string, value string) {
	mcm.mu.Lock()
	defer mcm.mu.Unlock()

	config, exists := mcm.configs[moduleID]
	if !exists {
		config = ModuleConfig{
			Enabled:     true,
			Settings:    make(map[string]interface{}),
			Environment: make(map[string]string),
		}
	}

	if config.Environment == nil {
		config.Environment = make(map[string]string)
	}

	config.Environment[key] = value
	mcm.configs[moduleID] = config
	mcm.logger.LogInfo("config_info", fmt.Sprintf("Updated environment %s for module %s", key, moduleID), nil)
}

// GetModuleEnvironment gets an environment variable for a module
func (mcm *ModuleConfigManager) GetModuleEnvironment(moduleID string, key string) (string, bool) {
	mcm.mu.RLock()
	defer mcm.mu.RUnlock()

	config, exists := mcm.configs[moduleID]
	if !exists {
		return "", false
	}

	value, exists := config.Environment[key]
	return value, exists
}

// createDefaultConfig creates a default configuration file
func (mcm *ModuleConfigManager) createDefaultConfig() error {
	defaultConfig := ModuleConfigFile{
		Modules: map[string]ModuleConfigEntry{
			"telemetry": {
				Type:     "telemetry",
				Enabled:  true,
				Priority: 1,
				Settings: map[string]interface{}{
					"buffer_size":     1000,
					"flush_interval":  "30s",
					"metrics_enabled": true,
				},
				Environment: make(map[string]string),
			},
			"communication": {
				Type:     "communication",
				Enabled:  true,
				Priority: 2,
				Settings: map[string]interface{}{
					"queue_size":       1000,
					"heartbeat_interval": "30s",
					"reconnect_interval": "5s",
				},
				Environment: make(map[string]string),
			},
		},
		Global: GlobalConfig{
			LogLevel:      "info",
			ModuleTimeout: 30,
			MaxRetries:    3,
			Environment: map[string]string{
				"AEGIS_ENV": "production",
			},
		},
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal default config: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(mcm.configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write to file
	if err := ioutil.WriteFile(mcm.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write default config file: %w", err)
	}

	mcm.logger.LogInfo("config_info", fmt.Sprintf("Created default module configuration: %s", mcm.configPath), nil)
	return nil
}

// ValidateConfig validates the module configuration
func (mcm *ModuleConfigManager) ValidateConfig() error {
	mcm.mu.RLock()
	defer mcm.mu.RUnlock()

	for moduleID, config := range mcm.configs {
		if err := mcm.validateModuleConfig(moduleID, config); err != nil {
			return fmt.Errorf("invalid config for module %s: %w", moduleID, err)
		}
	}

	return nil
}

// validateModuleConfig validates a single module configuration
func (mcm *ModuleConfigManager) validateModuleConfig(moduleID string, config ModuleConfig) error {
	// Check required fields
	if moduleID == "" {
		return fmt.Errorf("module ID cannot be empty")
	}

	// Validate priority
	if config.Priority < 0 {
		return fmt.Errorf("priority cannot be negative")
	}

	// Validate settings
	if config.Settings != nil {
		for key, value := range config.Settings {
			if key == "" {
				return fmt.Errorf("setting key cannot be empty")
			}
			if value == nil {
				return fmt.Errorf("setting value cannot be nil for key %s", key)
			}
		}
	}

	// Validate environment
	if config.Environment != nil {
		for key, value := range config.Environment {
			if key == "" {
				return fmt.Errorf("environment key cannot be empty")
			}
			if value == "" {
				return fmt.Errorf("environment value cannot be empty for key %s", key)
			}
		}
	}

	return nil
}

// GetEnabledModules returns all enabled modules
func (mcm *ModuleConfigManager) GetEnabledModules() []string {
	mcm.mu.RLock()
	defer mcm.mu.RUnlock()

	var enabled []string
	for moduleID, config := range mcm.configs {
		if config.Enabled {
			enabled = append(enabled, moduleID)
		}
	}

	return enabled
}

// GetModulesByPriority returns modules sorted by priority
func (mcm *ModuleConfigManager) GetModulesByPriority() []string {
	mcm.mu.RLock()
	defer mcm.mu.RUnlock()

	// Create a slice of module IDs with their priorities
	type modulePriority struct {
		ID       string
		Priority int
	}

	var modules []modulePriority
	for moduleID, config := range mcm.configs {
		if config.Enabled {
			modules = append(modules, modulePriority{
				ID:       moduleID,
				Priority: config.Priority,
			})
		}
	}

	// Sort by priority (lower numbers first)
	for i := 0; i < len(modules); i++ {
		for j := i + 1; j < len(modules); j++ {
			if modules[i].Priority > modules[j].Priority {
				modules[i], modules[j] = modules[j], modules[i]
			}
		}
	}

	// Extract module IDs
	var result []string
	for _, module := range modules {
		result = append(result, module.ID)
	}

	return result
}
