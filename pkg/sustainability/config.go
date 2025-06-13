package sustainability

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath = "/etc/sustainability/config.yaml"
)

type ConfigManager struct {
	log        *logging.Logger
	configPath string
	watcher    *fsnotify.Watcher
	config     atomic.Value // stores *SustainabilityConfig
	stopCh     chan struct{}
}

func NewConfigManager(log *logging.Logger, configPath string) (*ConfigManager, error) {
	if configPath == "" {
		configPath = DefaultConfigPath
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	cm := &ConfigManager{
		log:        log.WithField("component", "config-manager"),
		configPath: configPath,
		watcher:    watcher,
		stopCh:     make(chan struct{}),
	}

	// Load initial configuration
	config, err := cm.loadConfig()
	if err != nil {
		// If config file doesn't exist or is invalid, use defaults
		cm.log.Warnf("Failed to load config from %s, using defaults: %v", configPath, err)
		config = DefaultSustainabilityConfig()
	}
	cm.config.Store(config)

	// Start watching for config changes
	if err := cm.startWatching(); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to start config watching: %w", err)
	}

	return cm, nil
}

func (cm *ConfigManager) GetConfig() *SustainabilityConfig {
	return cm.config.Load().(*SustainabilityConfig)
}

func (cm *ConfigManager) startWatching() error {
	// Create config directory if it doesn't exist
	configDir := filepath.Dir(cm.configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create default config file if it doesn't exist
	if _, err := os.Stat(cm.configPath); os.IsNotExist(err) {
		if err := cm.writeDefaultConfig(); err != nil {
			cm.log.Warnf("Failed to create default config file: %v", err)
		}
	}

	// Add the config file to the watcher
	if err := cm.watcher.Add(configDir); err != nil {
		return fmt.Errorf("failed to watch config directory: %w", err)
	}

	// Start the watcher goroutine
	go cm.watchLoop()

	return nil
}

func (cm *ConfigManager) watchLoop() {
	for {
		select {
		case <-cm.stopCh:
			return
		case event, ok := <-cm.watcher.Events:
			if !ok {
				return
			}

			// Check if the event is for our config file
			if event.Name == cm.configPath {
				if event.Op&fsnotify.Write == fsnotify.Write {
					cm.log.Info("Config file updated, reloading...")
					cm.reloadConfig()
				}
			}
		case err, ok := <-cm.watcher.Errors:
			if !ok {
				return
			}
			cm.log.Errorf("Config watcher error: %v", err)
		}
	}
}

func (cm *ConfigManager) reloadConfig() {
	config, err := cm.loadConfig()
	if err != nil {
		cm.log.Errorf("Failed to reload config: %v", err)
		return
	}

	oldConfig := cm.config.Load().(*SustainabilityConfig)
	cm.config.Store(config)

	cm.log.Infof("Config reloaded successfully: carbon=%.2f gCO2e/kWh, cost=%.4f USD/kWh, interval=%ds",
		config.CarbonIntensityGCO2PerKWh,
		config.EnergyPriceUSDPerKWh,
		config.ScrapeIntervalSeconds)

	// Log changes
	if oldConfig.CarbonIntensityGCO2PerKWh != config.CarbonIntensityGCO2PerKWh {
		cm.log.Infof("Carbon intensity changed: %.2f -> %.2f gCO2e/kWh",
			oldConfig.CarbonIntensityGCO2PerKWh, config.CarbonIntensityGCO2PerKWh)
	}
	if oldConfig.EnergyPriceUSDPerKWh != config.EnergyPriceUSDPerKWh {
		cm.log.Infof("Energy price changed: %.4f -> %.4f USD/kWh",
			oldConfig.EnergyPriceUSDPerKWh, config.EnergyPriceUSDPerKWh)
	}
}

func (cm *ConfigManager) loadConfig() (*SustainabilityConfig, error) {
	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config SustainabilityConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	// Validate and set defaults
	if config.CarbonIntensityGCO2PerKWh <= 0 {
		config.CarbonIntensityGCO2PerKWh = DefaultCarbonFactor
	}
	if config.EnergyPriceUSDPerKWh <= 0 {
		config.EnergyPriceUSDPerKWh = DefaultCostFactor
	}
	if config.ScrapeIntervalSeconds <= 0 {
		config.ScrapeIntervalSeconds = 30
	}
	if config.WorkerCount <= 0 {
		config.WorkerCount = 10
	}

	return &config, nil
}

func (cm *ConfigManager) writeDefaultConfig() error {
	config := DefaultSustainabilityConfig()

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal default config: %w", err)
	}

	// Add a header comment
	header := `# Kvisor Sustainability Configuration
# This file controls carbon emissions and energy cost calculations
# 
# carbonIntensity: grams of CO2 equivalent per kWh for your region
# energyPrice: cost in USD per kWh
# scrapeInterval: how often to collect metrics (seconds)
# workerCount: number of concurrent scraping workers

`

	fullData := []byte(header + string(data))

	if err := os.WriteFile(cm.configPath, fullData, 0644); err != nil {
		return fmt.Errorf("failed to write default config: %w", err)
	}

	cm.log.Infof("Created default config file at %s", cm.configPath)
	return nil
}

func (cm *ConfigManager) UpdateConfig(carbonIntensity, energyPrice float64) error {
	config := cm.GetConfig()

	newConfig := &SustainabilityConfig{
		CarbonIntensityGCO2PerKWh: carbonIntensity,
		EnergyPriceUSDPerKWh:      energyPrice,
		ScrapeIntervalSeconds:     config.ScrapeIntervalSeconds,
		WorkerCount:               config.WorkerCount,
	}

	data, err := yaml.Marshal(newConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(cm.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	cm.log.Infof("Updated config: carbon=%.2f gCO2e/kWh, cost=%.4f USD/kWh",
		carbonIntensity, energyPrice)

	return nil
}

func (cm *ConfigManager) Stop() {
	close(cm.stopCh)
	if cm.watcher != nil {
		cm.watcher.Close()
	}
}
