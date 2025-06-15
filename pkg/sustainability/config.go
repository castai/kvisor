package sustainability

import (
	"gopkg.in/yaml.v3"
)

// ParseConfigFromYAML parses sustainability config from YAML data
func ParseConfigFromYAML(data []byte) (*SustainabilityConfig, error) {
	var config SustainabilityConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Validate and set defaults
	if config.CarbonIntensityGCO2PerKWh <= 0 {
		config.CarbonIntensityGCO2PerKWh = DefaultCarbonFactor
	}
	if config.EnergyPriceUSDPerKWh <= 0 {
		config.EnergyPriceUSDPerKWh = DefaultCostFactor
	}

	return &config, nil
}

func (c *SustainabilityConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}
