package hostfs

import (
	"encoding/json"
	"fmt"
	"os"
	"path"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type manifestHeader struct {
	MediaType types.MediaType `json:"mediaType"`
}

func (h HostFSReader) resolveManifest(imageID string) (*v1.Manifest, error) {
	path := path.Join(h.Config.ContentDir, blobs, alg, imageID)

	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var header manifestHeader
	err = json.Unmarshal(fileBytes, &header)
	if err != nil {
		return nil, err
	}

	if header.MediaType.IsImage() {
		var manifest v1.Manifest
		err = json.Unmarshal(fileBytes, &manifest)
		if err != nil {
			return nil, err
		}
		return &manifest, nil
	}

	if header.MediaType.IsIndex() {
		var list v1.IndexManifest
		err = json.Unmarshal(fileBytes, &list)
		if err != nil {
			return nil, err
		}

		for _, m := range list.Manifests {
			// TODO: might be too simple for non amd64/linux
			if matchingPlatform(h.Config.Platform, *m.Platform) {
				return h.readManifest(m.Digest.Hex)
			}
		}

		return nil, fmt.Errorf("manifest not found for platform: %s %s", h.Config.Platform.Architecture, h.Config.Platform.OS)
	}

	return nil, fmt.Errorf("unrecognised manifest mediatype %q", string(header.MediaType))
}

func (h HostFSReader) readManifest(imageID string) (*v1.Manifest, error) {
	path := path.Join(h.Config.ContentDir, blobs, alg, imageID)
	manifestBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var manifest v1.Manifest
	err = json.Unmarshal(manifestBytes, &manifest)
	if err != nil {
		return nil, err
	}

	return &manifest, nil
}

func matchingPlatform(first, second v1.Platform) bool {
	return first.OS == second.OS && first.Architecture == second.Architecture
}
