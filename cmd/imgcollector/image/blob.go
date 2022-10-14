package image

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/castai/sec-agent/cmd/imgcollector/image/hostfs"
)

func NewFromContainerdHostFS(imageID string) (types.Image, func(), error) {
	img, cleanup, err := hostfs.ContainerdImage(imageID)
	if err != nil {
		return nil, nil, err
	}
	return blobImage{
		Image: img,
		name:  imageID,
	}, cleanup, nil
}

type blobImage struct {
	hostfs.Image
	name string
}

func (b blobImage) Name() string {
	return b.name
}

func (b blobImage) ID() (string, error) {
	return ID(b)
}

func (b blobImage) LayerIDs() ([]string, error) {
	return LayerIDs(b)
}
