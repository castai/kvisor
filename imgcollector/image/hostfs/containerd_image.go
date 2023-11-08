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
	metadataReader := newContainerdMetadataReader(hash, cfg)
	metadata, err := metadataReader.readMetadata()
	if err != nil {
		return nil, fmt.Errorf("resolving manifest: %w", err)
	}

	config, configBytes, err := metadataReader.readConfig(metadata.Manifest.Config.Digest.String())
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	return &containerdBlobImage{
		manifest:    metadata.Manifest,
		index:       metadata.Index,
		config:      config,
		configBytes: configBytes,
		contentDir:  cfg.ContentDir,
		imgHash:     metadata.Digest,
	}, nil
}

func newContainerdMetadataReader(hash v1.Hash, cfg ContainerdHostFSConfig) *containerdMetadataReader {
	return &containerdMetadataReader{
		imgHash: hash,
		cfg:     cfg,
	}
}

// containerdMetadataReader is used to follow image references as described here:
// https://github.com/google/go-containerregistry/blob/main/images/ociimage.jpeg
type containerdMetadataReader struct {
	cfg     ContainerdHostFSConfig
	imgHash v1.Hash
}

type ContainerdHostFSConfig struct {
	Platform   v1.Platform
	ContentDir string
}

type containerdMetadata struct {
	Index    *v1.IndexManifest
	Manifest *v1.Manifest
	Digest   v1.Hash
}

type manifestOrIndex struct {
	SchemaVersion int64             `json:"schemaVersion"`
	MediaType     types.MediaType   `json:"mediaType,omitempty"`
	Config        v1.Descriptor     `json:"config"`
	Annotations   map[string]string `json:"annotations,omitempty"`

	// Layers contained in manifest.
	Layers []v1.Descriptor `json:"layers"`
	// Manifests contained in index manifest.
	Manifests []v1.Descriptor `json:"manifests"`
}

func readManifest(atPath string, into *manifestOrIndex) error {
	fileBytes, err := os.ReadFile(atPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(fileBytes, into)
}

// manifest part of the sum type
func (mi *manifestOrIndex) manifest() *v1.Manifest {
	return &v1.Manifest{
		SchemaVersion: mi.SchemaVersion,
		MediaType:     mi.MediaType,
		Config:        mi.Config,
		Layers:        mi.Layers,
		Annotations:   mi.Annotations,
	}
}

// index part of the sum type
func (mi *manifestOrIndex) index() *v1.IndexManifest {
	return &v1.IndexManifest{
		SchemaVersion: mi.SchemaVersion,
		MediaType:     mi.MediaType,
		Manifests:     mi.Manifests,
		Annotations:   mi.Annotations,
	}
}

func (h *containerdMetadataReader) readMetadata() (*containerdMetadata, error) {
	var (
		metadata containerdMetadata
		manOrIdx manifestOrIndex
	)

	metadata.Digest = h.imgHash
	if err := readManifest(
		path.Join(h.cfg.ContentDir, blobs, h.imgHash.Algorithm, h.imgHash.Hex), &manOrIdx,
	); err != nil {
		return nil, err
	}

	// This case indicates that image id digest points to config file.
	// In such case we need to find manifest by iterating all files and searching for
	// config file digest hash inside files content.
	if len(manOrIdx.Layers) == 0 && len(manOrIdx.Manifests) == 0 {
		manifestPath, filename, err := h.searchManifestPath()
		if err != nil {
			return nil, fmt.Errorf("searching manifest path: %w", err)
		}
		if err := readManifest(manifestPath, &manOrIdx); err != nil {
			return nil, err
		}

		metadata.Digest = v1.Hash{
			Algorithm: "sha256",
			Hex:       filename,
		}
	}

	if len(manOrIdx.Layers) > 0 {
		metadata.Manifest = manOrIdx.manifest()
		return &metadata, nil
	}

	// Search manifest from index manifest.
	if len(manOrIdx.Manifests) > 0 {
		metadata.Index = manOrIdx.index()
		for _, manifest := range manOrIdx.Manifests {
			if matchingPlatform(h.cfg.Platform, *manifest.Platform) {
				if err := readManifest(
					path.Join(h.cfg.ContentDir, blobs, manifest.Digest.Algorithm, manifest.Digest.Hex), &manOrIdx,
				); err != nil {
					return nil, err
				}
				if len(manOrIdx.Layers) == 0 {
					return nil, errors.New("invalid manifest, no layers")
				}
				metadata.Manifest = manOrIdx.manifest()
				metadata.Digest = manifest.Digest
				return &metadata, nil
			}
		}
		return nil, fmt.Errorf("manifest not found for platform: %s %s", h.cfg.Platform.Architecture, h.cfg.Platform.OS)
	}

	return nil, fmt.Errorf("unrecognised manifest mediatype %q", string(manOrIdx.MediaType))
}

func (h *containerdMetadataReader) readConfig(configID string) (*v1.ConfigFile, []byte, error) {
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

func (h *containerdMetadataReader) searchManifestPath() (string, string, error) {
	root := path.Join(h.cfg.ContentDir, blobs, h.imgHash.Algorithm)
	var manifestPath, filename string
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
			filename = info.Name()
			return io.EOF
		}
		return nil
	}); err != nil && !errors.Is(err, io.EOF) {
		return "", "", err
	}
	if manifestPath == "" {
		return "", "", errors.New("manifest not found by searching in blobs content")
	}
	return manifestPath, filename, nil
}

type containerdBlobImage struct {
	manifest    *v1.Manifest
	index       *v1.IndexManifest
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

func (b *containerdBlobImage) Index() *v1.IndexManifest {
	return b.index
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

func matchingPlatform(first, second v1.Platform) bool {
	return first.OS == second.OS && first.Architecture == second.Architecture
}
