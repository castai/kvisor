package castai

type SyncStateFilter struct {
	ImagesIds []string `json:"imagesIds"`
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
