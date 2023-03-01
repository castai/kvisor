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
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	// Skip files larger that 10kB when searching for manifest is slow path.
	maxManifestFileSizeBytes = 10240

	blobs = "blobs"
)

func NewContainerdImage(hash v1.Hash, cfg ContainerdHostFSConfig) (Image, error) {
	manifestReader := newContainerdManifestReader(hash, cfg)
	manifest, err := manifestReader.resolveManifest()
	if err != nil {
		return nil, fmt.Errorf("resolving manifest: %w", err)
	}

	config, configBytes, err := manifestReader.readConfig(manifest.Config.Digest.String())
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	img := &containerdBlobImage{
		manifest:    manifest,
		config:      config,
		configBytes: configBytes,
		contentDir:  cfg.ContentDir,
	}
	return img, nil
}

func newContainerdManifestReader(hash v1.Hash, cfg ContainerdHostFSConfig) *containerdManifestReader {
	return &containerdManifestReader{
		imgHash: hash,
		cfg:     cfg,
	}
}

type containerdManifestReader struct {
	cfg     ContainerdHostFSConfig
	imgHash v1.Hash
}

type ContainerdHostFSConfig struct {
	Platform   v1.Platform
	ContentDir string
}

func (h *containerdManifestReader) resolveManifest() (*v1.Manifest, error) {
	// Try to find manifest file. In most cases image id digest will point to manifest or index.
	var manifest v1.Manifest
	readManifest := func(manifestPath string) error {
		var err error
		fileBytes, err := os.ReadFile(manifestPath)
		if err != nil {
			return err
		}
		err = json.Unmarshal(fileBytes, &manifest)
		if err != nil {
			return err
		}
		return nil
	}
	if err := readManifest(path.Join(h.cfg.ContentDir, blobs, h.imgHash.Algorithm, h.imgHash.Hex)); err != nil {
		return nil, err
	}

	// This case indicates that image id digest points to config file.
	// In such case we need to find manifest by iterating all files and searching for
	// config file digest hash inside files content.
	if len(manifest.Layers) == 0 {
		manifestPath, err := h.searchManifestPath()
		if err != nil {
			return nil, fmt.Errorf("searching manifest path: %w", err)
		}
		if err := readManifest(manifestPath); err != nil {
			return nil, err
		}
	}

	if len(manifest.Layers) > 0 {
		return &manifest, nil
	}

	return nil, fmt.Errorf("unrecognised manifest mediatype %q", string(manifest.MediaType))
}

func (h *containerdManifestReader) readConfig(configID string) (*v1.ConfigFile, []byte, error) {
	p := strings.Split(configID, ":")
	if len(p) < 2 {
		return nil, nil, fmt.Errorf("invalid configID: %s", configID)
	}
	configPath := path.Join(h.cfg.ContentDir, blobs, p[0], p[1])

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, err
	}

	var cfg v1.ConfigFile
	err = json.Unmarshal(configBytes, &cfg)
	if err != nil {
		return nil, nil, err
	}

	return &cfg, configBytes, nil
}

func (h *containerdManifestReader) searchManifestPath() (string, error) {
	root := path.Join(h.cfg.ContentDir, blobs, h.imgHash.Algorithm)
	var manifestPath string
	digestBytes := []byte(h.imgHash.Hex)
	if err := filepath.Walk(root, func(path string, info fs.FileInfo, rerr error) error {
		if info.IsDir() {
			return nil
		}
		if info.Size() > maxManifestFileSizeBytes {
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

type containerdBlobImage struct {
	manifest    *v1.Manifest
	config      *v1.ConfigFile
	configBytes []byte
	imgHash     v1.Hash

	contentDir string
}

func (b *containerdBlobImage) Layers() ([]v1.Layer, error) {
	l := make([]v1.Layer, len(b.manifest.Layers))
	for i, lay := range b.manifest.Layers {
		layer, err := b.LayerByDigest(lay.Digest)
		if err != nil {
			return nil, err
		}
		l[i] = layer
	}

	return l, nil
}

func (b *containerdBlobImage) ConfigName() (v1.Hash, error) {
	return b.manifest.Config.Digest, nil
}

func (b *containerdBlobImage) ConfigFile() (*v1.ConfigFile, error) {
	return b.config, nil
}

func (b *containerdBlobImage) Manifest() (*v1.Manifest, error) {
	return b.manifest, nil
}

func (b *containerdBlobImage) RawConfigFile() ([]byte, error) {
	return b.configBytes, nil
}

func (b *containerdBlobImage) Digest() (v1.Hash, error) {
	return b.imgHash, nil
}

func (b *containerdBlobImage) LayerByDigest(hash v1.Hash) (v1.Layer, error) {
	layerPath := path.Join(b.contentDir, blobs, hash.Algorithm, hash.Hex)
	return tarball.LayerFromFile(layerPath)
}

func (b *containerdBlobImage) LayerByDiffID(hash v1.Hash) (v1.Layer, error) {
	var idx int
	for i, diff := range b.config.RootFS.DiffIDs {
		if diff.Hex == hash.Hex {
			idx = i
			break
		}
	}

	l := b.manifest.Layers[idx]
	return b.LayerByDigest(l.Digest)
}

// currently unused

func (b *containerdBlobImage) MediaType() (types.MediaType, error) {
	//TODO implement me
	panic("implement me")
}

func (b *containerdBlobImage) Size() (int64, error) {
	//TODO implement me
	panic("implement me")
}

func (b *containerdBlobImage) RawManifest() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (b *containerdBlobImage) RepoTags() []string {
	//TODO implement me
	panic("implement me")
}

func (b *containerdBlobImage) RepoDigests() []string {
	//TODO implement me
	panic("implement me")
}
