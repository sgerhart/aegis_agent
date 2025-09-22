package modules

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"plugin"
	"strings"
	"sync"

	"agents/aegis/internal/telemetry"
)

// ModuleFactoryImpl implements the ModuleFactory interface
type ModuleFactoryImpl struct {
	factories map[string]func(ModuleConfig) (ModuleInterface, error)
	logger    *telemetry.Logger
}

// NewModuleFactory creates a new module factory
func NewModuleFactory(logger *telemetry.Logger) *ModuleFactoryImpl {
	return &ModuleFactoryImpl{
		factories: make(map[string]func(ModuleConfig) (ModuleInterface, error)),
		logger:    logger,
	}
}

// CreateModule creates a module instance
func (mf *ModuleFactoryImpl) CreateModule(moduleType string, config ModuleConfig) (ModuleInterface, error) {
	factory, exists := mf.factories[moduleType]
	if !exists {
		return nil, fmt.Errorf("module type %s not supported", moduleType)
	}
	
	return factory(config)
}

// GetSupportedTypes returns all supported module types
func (mf *ModuleFactoryImpl) GetSupportedTypes() []string {
	types := make([]string, 0, len(mf.factories))
	for moduleType := range mf.factories {
		types = append(types, moduleType)
	}
	return types
}

// RegisterFactory registers a factory function for a module type
func (mf *ModuleFactoryImpl) RegisterFactory(moduleType string, factory func(ModuleConfig) (ModuleInterface, error)) error {
	if _, exists := mf.factories[moduleType]; exists {
		return fmt.Errorf("module type %s already registered", moduleType)
	}
	
	mf.factories[moduleType] = factory
	mf.logger.LogInfo("factory_registered", fmt.Sprintf("Registered factory for module type: %s", moduleType), nil)
	
	return nil
}

// UnregisterFactory unregisters a factory function
func (mf *ModuleFactoryImpl) UnregisterFactory(moduleType string) error {
	if _, exists := mf.factories[moduleType]; !exists {
		return fmt.Errorf("module type %s not registered", moduleType)
	}
	
	delete(mf.factories, moduleType)
	mf.logger.LogInfo("factory_unregistered", fmt.Sprintf("Unregistered factory for module type: %s", moduleType), nil)
	
	return nil
}

// ModuleLoaderImpl implements the ModuleLoader interface
type ModuleLoaderImpl struct {
	factory *ModuleFactoryImpl
	logger  *telemetry.Logger
}

// NewModuleLoader creates a new module loader
func NewModuleLoader(factory *ModuleFactoryImpl, logger *telemetry.Logger) *ModuleLoaderImpl {
	return &ModuleLoaderImpl{
		factory: factory,
		logger:  logger,
	}
}

// LoadFromPath loads a module from a file path
func (ml *ModuleLoaderImpl) LoadFromPath(path string) (ModuleInterface, error) {
	// Check if it's a Go plugin
	if strings.HasSuffix(path, ".so") {
		return ml.loadPlugin(path)
	}
	
	// Check if it's a configuration file
	if strings.HasSuffix(path, ".json") {
		return ml.LoadFromConfig(path)
	}
	
	return nil, fmt.Errorf("unsupported module file type: %s", path)
}

// LoadFromConfig loads a module from a configuration file
func (ml *ModuleLoaderImpl) LoadFromConfig(configPath string) (ModuleInterface, error) {
	_, err := ml.loadConfigFromFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	
	// For now, return a dummy module since we don't have type information
	return nil, fmt.Errorf("module type not specified in config")
}

// LoadFromRegistry loads a module from the registry
func (ml *ModuleLoaderImpl) LoadFromRegistry(moduleType string, config ModuleConfig) (ModuleInterface, error) {
	return ml.factory.CreateModule(moduleType, config)
}

// Unload unloads a module
func (ml *ModuleLoaderImpl) Unload(moduleID string) error {
	// For statically linked modules, we can't actually unload them
	// This would be more relevant for dynamically loaded plugins
	ml.logger.LogInfo("loader_info", fmt.Sprintf("Module unloaded: %s", moduleID), nil)
	return nil
}

// loadPlugin loads a Go plugin
func (ml *ModuleLoaderImpl) loadPlugin(pluginPath string) (ModuleInterface, error) {
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin %s: %w", pluginPath, err)
	}
	
	// Look for the NewModule symbol
	newModuleSymbol, err := p.Lookup("NewModule")
	if err != nil {
		return nil, fmt.Errorf("plugin %s does not export NewModule function: %w", pluginPath, err)
	}
	
	// Cast to the expected function signature
	newModule, ok := newModuleSymbol.(func(ModuleConfig) (ModuleInterface, error))
	if !ok {
		return nil, fmt.Errorf("plugin %s NewModule function has wrong signature", pluginPath)
	}
	
	// Create module with default config
	config := ModuleConfig{Enabled: true}
	return newModule(config)
}

// loadConfigFromFile loads configuration from a file
func (ml *ModuleLoaderImpl) loadConfigFromFile(configPath string) (ModuleConfig, error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return ModuleConfig{}, fmt.Errorf("failed to read config file: %w", err)
	}
	
	var config struct {
		Type        string                 `json:"type"`
		Enabled     bool                   `json:"enabled"`
		Priority    int                    `json:"priority"`
		Settings    map[string]interface{} `json:"settings"`
		Environment map[string]string      `json:"environment"`
	}
	
	if err := json.Unmarshal(data, &config); err != nil {
		return ModuleConfig{}, fmt.Errorf("failed to parse config file: %w", err)
	}
	
	return ModuleConfig{
		Enabled:     config.Enabled,
		Priority:    config.Priority,
		Settings:    config.Settings,
		Environment: config.Environment,
	}, nil
}

// DependencyManagerImpl implements the DependencyManager interface
type DependencyManagerImpl struct {
	dependencies map[string][]ModuleDependency // moduleID -> dependencies
	dependents   map[string][]string           // moduleID -> dependents
	mu           sync.RWMutex
	logger       *telemetry.Logger
}

// NewDependencyManager creates a new dependency manager
func NewDependencyManager(logger *telemetry.Logger) *DependencyManagerImpl {
	return &DependencyManagerImpl{
		dependencies: make(map[string][]ModuleDependency),
		dependents:   make(map[string][]string),
		logger:       logger,
	}
}

// AddDependency adds a dependency for a module
func (dm *DependencyManagerImpl) AddDependency(moduleID string, dependency ModuleDependency) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	
	// Add to dependencies
	dm.dependencies[moduleID] = append(dm.dependencies[moduleID], dependency)
	
	// Add to dependents
	dm.dependents[dependency.DependencyID] = append(dm.dependents[dependency.DependencyID], moduleID)
	
	dm.logger.LogInfo("dependency_info", fmt.Sprintf("Added dependency: %s depends on %s", moduleID, dependency.DependencyID), nil)
	return nil
}

// RemoveDependency removes a dependency
func (dm *DependencyManagerImpl) RemoveDependency(moduleID string, dependencyID string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	
	// Remove from dependencies
	if deps, exists := dm.dependencies[moduleID]; exists {
		for i, dep := range deps {
			if dep.DependencyID == dependencyID {
				dm.dependencies[moduleID] = append(deps[:i], deps[i+1:]...)
				break
			}
		}
	}
	
	// Remove from dependents
	if dependents, exists := dm.dependents[dependencyID]; exists {
		for i, dependent := range dependents {
			if dependent == moduleID {
				dm.dependents[dependencyID] = append(dependents[:i], dependents[i+1:]...)
				break
			}
		}
	}
	
	dm.logger.LogInfo("dependency_info", fmt.Sprintf("Removed dependency: %s no longer depends on %s", moduleID, dependencyID), nil)
	return nil
}

// GetDependencies returns dependencies for a module
func (dm *DependencyManagerImpl) GetDependencies(moduleID string) []ModuleDependency {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	deps := make([]ModuleDependency, len(dm.dependencies[moduleID]))
	copy(deps, dm.dependencies[moduleID])
	return deps
}

// GetDependents returns modules that depend on the given module
func (dm *DependencyManagerImpl) GetDependents(moduleID string) []string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	dependents := make([]string, len(dm.dependents[moduleID]))
	copy(dependents, dm.dependents[moduleID])
	return dependents
}

// ResolveDependencies resolves and returns dependency modules
func (dm *DependencyManagerImpl) ResolveDependencies(moduleID string) ([]ModuleInterface, error) {
	// This would typically interact with the module manager to get actual module instances
	// For now, return an empty list
	return []ModuleInterface{}, nil
}

// CheckDependencies checks if all dependencies are satisfied
func (dm *DependencyManagerImpl) CheckDependencies(moduleID string) error {
	deps := dm.GetDependencies(moduleID)
	
	for _, dep := range deps {
		if dep.Required {
			// Check if the dependency module exists and is running
			// This would typically check with the module manager
			dm.logger.LogDebug("dependency_debug", fmt.Sprintf("Checking required dependency: %s -> %s", moduleID, dep.DependencyID), nil)
		}
	}
	
	return nil
}

// ModuleDiscovery discovers modules from various sources
type ModuleDiscovery struct {
	searchPaths []string
	logger      *telemetry.Logger
}

// NewModuleDiscovery creates a new module discovery
func NewModuleDiscovery(logger *telemetry.Logger) *ModuleDiscovery {
	return &ModuleDiscovery{
		searchPaths: []string{"./modules", "/usr/local/lib/aegis/modules", "/opt/aegis/modules"},
		logger:      logger,
	}
}

// DiscoverModules discovers available modules
func (md *ModuleDiscovery) DiscoverModules() ([]string, error) {
	var modules []string
	
	for _, path := range md.searchPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		
		files, err := ioutil.ReadDir(path)
		if err != nil {
			md.logger.LogWarn("discovery_warn", fmt.Sprintf("Failed to read module directory %s: %v", path, err), nil)
			continue
		}
		
		for _, file := range files {
			if file.IsDir() {
				// Check for module.json in the directory
				configPath := filepath.Join(path, file.Name(), "module.json")
				if _, err := os.Stat(configPath); err == nil {
					modules = append(modules, configPath)
				}
			} else if strings.HasSuffix(file.Name(), ".so") {
				// Go plugin
				modules = append(modules, filepath.Join(path, file.Name()))
			} else if strings.HasSuffix(file.Name(), ".json") {
				// Configuration file
				modules = append(modules, filepath.Join(path, file.Name()))
			}
		}
	}
	
	return modules, nil
}

// AddSearchPath adds a search path for module discovery
func (md *ModuleDiscovery) AddSearchPath(path string) {
	md.searchPaths = append(md.searchPaths, path)
}

// GetSearchPaths returns all search paths
func (md *ModuleDiscovery) GetSearchPaths() []string {
	return md.searchPaths
}
