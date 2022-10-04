package castai

type TelemetryResponse struct {
	DisabledFeatures []string `json:"disabledFeatures"`
	FullResync       bool     `json:"fullResync"`
}
