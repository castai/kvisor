package hostfs

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type manifestHeader struct {
	MediaType types.MediaType `json:"mediaType"`
}

func resolveManifest(imageID string) (*v1.Manifest, error) {
	path := path.Join(contentDir, blobs, alg, imageID)

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
		platform := v1.Platform{
			// TODO: allow mocking
			Architecture: runtime.GOARCH,
			//Architecture: "amd64",
			OS: runtime.GOOS,
			//OS: "linux",
		}

		var list v1.IndexManifest
		err = json.Unmarshal(fileBytes, &list)
		if err != nil {
			return nil, err
		}

		for _, m := range list.Manifests {
			// TODO: might be too simple for non amd64/linux
			if matchingPlatform(platform, *m.Platform) {
				return readManifest(m.Digest.Hex)
			}
		}

		return nil, fmt.Errorf("manifest not found for platform: %s %s", platform.Architecture, platform.OS)
	}

	return nil, fmt.Errorf("unrecognised manifest mediatype")
}

func readManifest(imageID string) (*v1.Manifest, error) {
	path := path.Join(contentDir, blobs, alg, imageID)
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
