package image

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/castai/kvisor/cmd/imgcollector/image/daemon"
)

type Image = types.Image

func NewFromContainerdDaemon(ctx context.Context, imageName string) (types.Image, func(), error) {
	img, cleanup, err := daemon.ContainerdImage(ctx, imageName)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

func NewFromDockerDaemon(imageName string, ref name.Reference) (types.Image, func(), error) {
	img, cleanup, err := daemon.DockerImage(ref)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

func NewFromDockerDaemonTarFile(imageName, localTarPath string, ref name.Reference) (types.Image, func(), error) {
	img, cleanup, err := daemon.DockerTarImage(ref, localTarPath)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

type daemonImage struct {
	daemon.Image
	name string
}

func (d daemonImage) Name() string {
	return d.name
}

func (d daemonImage) ID() (string, error) {
	return ID(d)
}

func (d daemonImage) LayerIDs() ([]string, error) {
	return LayerIDs(d)
}
