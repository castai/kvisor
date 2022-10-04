package castai

type TelemetryResponse struct {
	DisabledFeatures []string `json:"disabled_features"`
	FullResync       bool     `json:"full_resync"`
}
