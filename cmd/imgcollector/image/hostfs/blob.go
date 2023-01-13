package hostfs

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	// TODO: OCI also supports sha512
	alg   = "sha256"
	blobs = "blobs"
)

type HostFSReader struct {
	Config ContainerdHostFSConfig
}

type ContainerdHostFSConfig struct {
	Platform   v1.Platform
	ContentDir string
}

type Image interface {
	v1.Image
	RepoTags() []string
	RepoDigests() []string
}

type blobImage struct {
	manifest    *v1.Manifest
	config      *v1.ConfigFile
	configBytes []byte
	imageID     string

	contentDir string
}

func (b blobImage) Layers() ([]v1.Layer, error) {
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

func (b blobImage) ConfigName() (v1.Hash, error) {
	return b.manifest.Config.Digest, nil
}

func (b blobImage) ConfigFile() (*v1.ConfigFile, error) {
	return b.config, nil
}

func (b blobImage) Manifest() (*v1.Manifest, error) {
	return b.manifest, nil
}

func (b blobImage) RawConfigFile() ([]byte, error) {
	return b.configBytes, nil
}

func (b blobImage) Digest() (v1.Hash, error) {
	return v1.Hash{
		Algorithm: alg,
		Hex:       b.imageID,
	}, nil
}

func (b blobImage) LayerByDigest(hash v1.Hash) (v1.Layer, error) {
	layerPath := path.Join(b.contentDir, blobs, alg, hash.Hex)
	return tarball.LayerFromFile(layerPath)
}

func (b blobImage) LayerByDiffID(hash v1.Hash) (v1.Layer, error) {
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

func (h HostFSReader) ContainerdImage(imageID string) (Image, func(), error) {
	manifest, err := h.resolveManifest(imageID)
	if err != nil {
		return nil, nil, err
	}

	config, bytes, err := h.readConfig(manifest.Config.Digest.String())
	if err != nil {
		return nil, nil, err
	}

	i := blobImage{
		manifest:    manifest,
		config:      config,
		configBytes: bytes,
		contentDir:  h.Config.ContentDir,
	}

	return i, cleanup, nil
}

func (h HostFSReader) readConfig(configID string) (*v1.ConfigFile, []byte, error) {
	p := strings.Split(configID, ":")
	if len(p) < 2 {
		return nil, nil, fmt.Errorf("invalid configID: %s", configID)
	}
	configPath := path.Join(h.Config.ContentDir, blobs, p[0], p[1])

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

func cleanup() {
	// noop
}

// currently unused

func (b blobImage) MediaType() (types.MediaType, error) {
	//TODO implement me
	panic("implement me")
}

func (b blobImage) Size() (int64, error) {
	//TODO implement me
	panic("implement me")
}

func (b blobImage) RawManifest() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (b blobImage) RepoTags() []string {
	//TODO implement me
	panic("implement me")
}

func (b blobImage) RepoDigests() []string {
	//TODO implement me
	panic("implement me")
}
