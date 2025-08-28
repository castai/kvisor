package sustainability

const (
	KeplerContainerEnergyJoulesMetric = "kepler_container_energy_joules"
)

// Sustainability calculation constants
const (
	// DefaultCarbonIntensityGCO2PerKWh represents the carbon intensity in grams of CO2 equivalent per kWh
	// This is a global average value - for demo purposes only
	DefaultCarbonIntensityGCO2PerKWh = 475.0

	// DefaultEnergyPriceUSDPerKWh represents the default energy price in USD per kWh
	// This is an average value - for demo purposes only
	DefaultEnergyPriceUSDPerKWh = 0.165

	// JoulesToKWhConversionFactor converts Joules to kilowatt-hours
	// 1 kWh = 3,600,000 Joules
	JoulesToKWhConversionFactor = 3_600_000.0
)

// CalculateCarbonEmissions calculates carbon emissions in grams of CO2 equivalent
func CalculateCarbonEmissions(energyJoules, carbonIntensityGCO2PerKWh float64) float64 {
	return (energyJoules / JoulesToKWhConversionFactor) * carbonIntensityGCO2PerKWh
}

// CalculateEnergyCost calculates energy cost in USD
func CalculateEnergyCost(energyJoules, energyPriceUSDPerKWh float64) float64 {
	return (energyJoules / JoulesToKWhConversionFactor) * energyPriceUSDPerKWh
}
