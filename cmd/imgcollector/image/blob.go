package image

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/castai/sec-agent/cmd/imgcollector/image/hostfs"
)

func NewFromContainerdHostFS(imageID string, config *hostfs.ContainerdHostFSConfig) (types.Image, func(), error) {
	hostFsReader := hostfs.HostFSReader{
		Config: *config,
	}
	img, cleanup, err := hostFsReader.ContainerdImage(imageID)
	if err != nil {
		return nil, nil, err
	}
	return extendedBlobImage{
		Image: img,
		name:  imageID,
	}, cleanup, nil
}

type extendedBlobImage struct {
	hostfs.Image
	name string
}

func (b extendedBlobImage) Name() string {
	return b.name
}

func (b extendedBlobImage) ID() (string, error) {
	return ID(b)
}

func (b extendedBlobImage) LayerIDs() ([]string, error) {
	return LayerIDs(b)
}
