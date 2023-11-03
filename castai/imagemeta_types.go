package castai

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type ImageMetadata struct {
	ImageName    string           `json:"imageName,omitempty"`
	ImageID      string           `json:"imageID,omitempty"`
	ImageDigest  string           `json:"imageDigest,omitempty"`
	ResourceIDs  []string         `json:"resourceIDs,omitempty"`
	Architecture string           `json:"architecture,omitempty"`
	BlobsInfo    []types.BlobInfo `json:"blobsInfo,omitempty"`
	ConfigFile   *v1.ConfigFile   `json:"configFile,omitempty"`
	// Manifest specification can be found here: https://github.com/opencontainers/image-spec/blob/main/manifest.md
	Manifest *v1.Manifest `json:"manifest,omitempty"`
	// Index specification can be found here: https://github.com/opencontainers/image-spec/blob/main/image-index.md
	Index  *v1.IndexManifest `json:"index,omitempty"`
	OsInfo *OsInfo           `json:"osInfo,omitempty"`
}

// nolint:musttag
type OsInfo struct {
	*types.ArtifactInfo `json:",inline"`
	*types.OS           `json:",inline"`
}

const (
	ImageScanStatusPending ImageScanStatus = "pending"
	ImageScanStatusError   ImageScanStatus = "error"
)

type ImageScanStatus string

type UpdateImagesStatusRequest struct {
	FullSnapshot bool    `json:"full_snapshot,omitempty"`
	Images       []Image `json:"images"`
}

type Image struct {
	ID              string          `json:"id"`
	Architecture    string          `json:"architecture"`
	ImageName       string          `json:"imageName"`
	ResourcesChange ResourcesChange `json:"resourcesChange"`
	Status          ImageScanStatus `json:"status,omitempty"`
	ErrorMsg        string          `json:"errorMsg,omitempty"`
}

type ResourcesChange struct {
	ResourceIDs []string `json:"resourceIDs"`
}
