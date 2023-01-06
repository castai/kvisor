package image

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/castai/kvisor/cmd/imgcollector/image/hostfs"
)

func NewFromContainerdHostFS(imageID string, config *hostfs.ContainerdHostFSConfig) (types.Image, func(), error) {
	hostFsReader := hostfs.HostFSReader{
		Config: *config,
	}

	digest := getDigestFromImageID(imageID)
	img, cleanup, err := hostFsReader.ContainerdImage(digest)
	if err != nil {
		return nil, nil, err
	}
	return extendedBlobImage{
		Image: img,
		name:  digest,
	}, cleanup, nil
}

func getDigestFromImageID(imageID string) string {
	s := strings.Split(imageID, ":")
	if len(s) == 1 {
		return s[0]
	}
	return s[len(s)-1]
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
