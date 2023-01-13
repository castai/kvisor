package hostfs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type manifestHeader struct {
	MediaType types.MediaType `json:"mediaType"`
}

func (h HostFSReader) resolveManifest(imageID string) (*v1.Manifest, error) {
	// Try to find manifest file. In most cases image id digest will point to manifest.
	var fileBytes []byte
	var header manifestHeader
	readManifest := func(manifestPath string) error {
		var err error
		fileBytes, err = os.ReadFile(manifestPath)
		if err != nil {
			return err
		}
		err = json.Unmarshal(fileBytes, &header)
		if err != nil {
			return err
		}
		return nil
	}
	if err := readManifest(path.Join(h.Config.ContentDir, blobs, alg, imageID)); err != nil {
		return nil, err
	}

	// Empty media type indicates that image id digest points to config file.
	// In such case we need to find manifest file by iterating all files.
	if header.MediaType == "" {
		manifestPath, err := h.searchManifestPath(imageID)
		if err != nil {
			return nil, fmt.Errorf("searching manifest path: %w", err)
		}
		if err := readManifest(manifestPath); err != nil {
			return nil, err
		}
	}

	if header.MediaType.IsImage() {
		var manifest v1.Manifest
		err := json.Unmarshal(fileBytes, &manifest)
		if err != nil {
			return nil, err
		}
		return &manifest, nil
	}

	if header.MediaType.IsIndex() {
		var list v1.IndexManifest
		err := json.Unmarshal(fileBytes, &list)
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
	manifestPath := path.Join(h.Config.ContentDir, blobs, alg, imageID)
	manifestBytes, err := os.ReadFile(manifestPath)
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

func (h HostFSReader) searchManifestPath(digest string) (string, error) {
	root := path.Join(h.Config.ContentDir, blobs, alg)
	var manifestPath string
	digestBytes := []byte(digest)
	if err := filepath.Walk(root, func(path string, info fs.FileInfo, rerr error) error {
		if info.IsDir() {
			return nil
		}
		// Skip files larger that 10kB.
		if info.Size() > 10240 {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(content, digestBytes) {
			manifestPath = path
			return io.EOF
		}
		return nil
	}); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return manifestPath, nil
}

func matchingPlatform(first, second v1.Platform) bool {
	return first.OS == second.OS && first.Architecture == second.Architecture
}
