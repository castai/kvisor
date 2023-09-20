package castai

type SyncStateFilter struct {
	Images []SyncStateFilterImage `json:"images"`
}

type SyncStateFilterImage struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Architecture string `json:"architecture"`
}

type SyncStateResponse struct {
	ScannedImages []ScannedImage `json:"scannedImages"`
}

type ScannedImage struct {
	ID           string   `json:"id"`
	Architecture string   `json:"architecture"`
	ResourceIDs  []string `json:"resourceIds"`
}

func (s ScannedImage) CacheKey() string {
	return s.ID + s.Architecture
}
