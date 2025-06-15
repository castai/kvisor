package sustainability

// Shared utility functions for sustainability calculations
// Used by both agents and controller

const (
	DefaultCarbonFactor = 415.7 // gCO2e/kWh (US average)
	DefaultCostFactor   = 0.12  // USD/kWh
)

// SustainabilityConfig holds configuration for carbon and cost calculations
type SustainabilityConfig struct {
	// Carbon intensity in grams of CO2 equivalent per kWh
	CarbonIntensityGCO2PerKWh float64 `yaml:"carbonIntensity" json:"carbonIntensity"`

	// Energy price in USD per kWh
	EnergyPriceUSDPerKWh float64 `yaml:"energyPrice" json:"energyPrice"`
}

// DefaultSustainabilityConfig returns a config with sensible defaults
func DefaultSustainabilityConfig() *SustainabilityConfig {
	return &SustainabilityConfig{
		CarbonIntensityGCO2PerKWh: DefaultCarbonFactor,
		EnergyPriceUSDPerKWh:      DefaultCostFactor,
	}
}

// ConvertJoulesToKWh converts joules to kilowatt-hours
func ConvertJoulesToKWh(joules float64) float64 {
	return joules / 3600000 // 1 kWh = 3,600,000 J
}

// CalculateCarbonEmissions calculates CO2 emissions in grams
func CalculateCarbonEmissions(joules, carbonIntensityGCO2PerKWh float64) float64 {
	kwh := ConvertJoulesToKWh(joules)
	return kwh * carbonIntensityGCO2PerKWh
}

// CalculateEnergyCost calculates energy cost in USD
func CalculateEnergyCost(joules, energyPriceUSDPerKWh float64) float64 {
	kwh := ConvertJoulesToKWh(joules)
	return kwh * energyPriceUSDPerKWh
}
