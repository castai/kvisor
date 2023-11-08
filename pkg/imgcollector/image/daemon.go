package image

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"

	daemon2 "github.com/castai/kvisor/pkg/imgcollector/image/daemon"
)

func NewFromContainerdDaemon(ctx context.Context, imageName string) (ImageWithIndex, func(), error) {
	img, cleanup, err := daemon2.ContainerdImage(ctx, imageName)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

func NewFromDockerDaemon(imageName string, ref name.Reference) (ImageWithIndex, func(), error) {
	img, cleanup, err := daemon2.DockerImage(ref)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

func NewFromDockerDaemonTarFile(imageName, localTarPath string, ref name.Reference) (ImageWithIndex, func(), error) {
	img, cleanup, err := daemon2.DockerTarImage(ref, localTarPath)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

type daemonImage struct {
	daemon2.Image
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
