package hostfs

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"
)

func TestContainerdImage(t *testing.T) {
	// This is expected case. Kubernetes pod imageID points to manifest file.
	t.Run("build image by manifest digest", func(t *testing.T) {
		r := require.New(t)
		hash := v1.Hash{
			Algorithm: "sha256",
			Hex:       "424f307cf3a1d20b3a512ae036bd2f0c66f395e20b62f583b7878773df4dc7fc",
		}
		img, err := NewContainerdImage(hash, ContainerdHostFSConfig{
			Platform:   v1.Platform{},
			ContentDir: "./testdata/containerd_content",
		})
		r.NoError(err)
		layers, err := img.Layers()
		r.NoError(err)
		r.Len(layers, 2)
		manifest, err := img.Manifest()
		r.NoError(err)
		r.Len(manifest.Layers, 2)
		config, err := img.ConfigFile()
		r.NoError(err)
		r.Len(config.RootFS.DiffIDs, 2)
	})

	// For old images kubernetes pod imageID could point to config file.
	t.Run("build image by config digest", func(t *testing.T) {
		r := require.New(t)
		hash := v1.Hash{
			Algorithm: "sha256",
			Hex:       "bf654875f3d9c5c34078387621f1978b97a01ca0fda74e0308b9bed664c9bbd7",
		}
		img, err := NewContainerdImage(hash, ContainerdHostFSConfig{
			Platform:   v1.Platform{},
			ContentDir: "./testdata/containerd_content",
		})
		r.NoError(err)
		layers, err := img.Layers()
		r.NoError(err)
		r.Len(layers, 2)
		manifest, err := img.Manifest()
		r.NoError(err)
		r.Len(manifest.Layers, 2)
		config, err := img.ConfigFile()
		r.NoError(err)
		r.Len(config.RootFS.DiffIDs, 2)
	})
}
