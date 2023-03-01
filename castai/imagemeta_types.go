package castai

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type ImageMetadata struct {
	ImageName   string           `json:"imageName,omitempty"`
	ImageID     string           `json:"imageID,omitempty"`
	ResourceIDs []string         `json:"resourceIDs,omitempty"`
	BlobsInfo   []types.BlobInfo `json:"blobsInfo,omitempty"`
	ConfigFile  *v1.ConfigFile   `json:"configFile,omitempty"`
	OsInfo      *OsInfo          `json:"osInfo,omitempty"`
}

// nolint:musttag
type OsInfo struct {
	*types.ArtifactInfo `json:",inline"`
	*types.OS           `json:",inline"`
}
