package castai

type TelemetryResponse struct {
	DisabledFeatures []string       `json:"disabledFeatures"`
	FullResync       bool           `json:"fullResync"`
	ScannedImages    []ScannedImage `json:"scannedImages"`
	NodeIDs          []string       `json:"nodeIds"`
	EnforcedRules    []string       `json:"enforcedRules"`
}
