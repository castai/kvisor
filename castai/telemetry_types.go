package castai

type TelemetryResponse struct {
	DisabledFeatures []string       `json:"disabledFeatures"`
	FullResync       bool           `json:"fullResync"`
	ScannedImages    []ScannedImage `json:"scannedImages"`
	NodeIDs          []string       `json:"nodeIds"`
}

type ScannedImage struct {
	ID           string   `json:"id"`
	Architecture string   `json:"architecture"`
	ResourceIDs  []string `json:"resourceIds"`
}

func (s ScannedImage) CacheKey() string {
	return s.ID + s.Architecture
}
