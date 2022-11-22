package castai

type TelemetryResponse struct {
	DisabledFeatures []string       `json:"disabledFeatures"`
	FullResync       bool           `json:"fullResync"`
	ScannedImages    []ScannedImage `json:"scannedImages"`
	NodeIDs          []string       `json:"nodeIds"`
}

type ScannedImage struct {
	ID          string   `json:"id"`
	ResourceIDs []string `json:"resourceIds"`
}
