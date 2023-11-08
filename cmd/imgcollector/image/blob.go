package image

import (
	"github.com/castai/kvisor/cmd/imgcollector/image/hostfs"
)

func NewFromContainerdHostFS(imageID string, config hostfs.ContainerdHostFSConfig) (ImageWithIndex, func(), error) {
	hash, err := hostfs.NewImageHash(imageID)
	if err != nil {
		return nil, nil, err
	}
	img, err := hostfs.NewContainerdImage(hash, config)
	if err != nil {
		return nil, nil, err
	}
	return extendedBlobImage{
		Image: img,
		name:  hash.Hex,
	}, func() {}, nil
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
