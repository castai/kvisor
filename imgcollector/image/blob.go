package image

import (
	hostfs2 "github.com/castai/kvisor/imgcollector/image/hostfs"
)

func NewFromContainerdHostFS(imageID string, config hostfs2.ContainerdHostFSConfig) (ImageWithIndex, func(), error) {
	hash, err := hostfs2.NewImageHash(imageID)
	if err != nil {
		return nil, nil, err
	}
	img, err := hostfs2.NewContainerdImage(hash, config)
	if err != nil {
		return nil, nil, err
	}
	return extendedBlobImage{
		Image: img,
		name:  hash.Hex,
	}, func() {}, nil
}

type extendedBlobImage struct {
	hostfs2.Image
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
