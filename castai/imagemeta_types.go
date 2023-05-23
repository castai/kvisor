package castai

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type ImageMetadata struct {
	ImageName   string           `json:"imageName,omitempty"`
	ImageID     string           `json:"imageID,omitempty"`
	ImageDigest string           `json:"imageDigest,omitempty"`
	ResourceIDs []string         `json:"resourceIDs,omitempty"`
	BlobsInfo   []types.BlobInfo `json:"blobsInfo,omitempty"`
	ConfigFile  *v1.ConfigFile   `json:"configFile,omitempty"`
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
