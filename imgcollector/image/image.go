package image

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type Image = types.Image

type ImageWithIndex interface {
	Image
	Index() *v1.IndexManifest
}

func ID(img v1.Image) (string, error) {
	h, err := img.ConfigName()
	if err != nil {
		return "", fmt.Errorf("unable to get the image ID: %w", err)
	}
	return h.String(), nil
}

func LayerIDs(img v1.Image) ([]string, error) {
	conf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("unable to get the config file: %w", err)
	}

	var layerIDs []string
	for _, d := range conf.RootFS.DiffIDs {
		layerIDs = append(layerIDs, d.String())
	}
	return layerIDs, nil
}

func NamespacedRegistry(ref name.Reference) string {
	fullName := ref.Context().Name()
	parts := strings.Split(fullName, "/")
	return strings.Join(parts[:2], "/")
}
