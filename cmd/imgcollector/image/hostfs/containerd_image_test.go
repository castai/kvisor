package hostfs

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"
)

func TestContainerdImage(t *testing.T) {
	tests := []struct {
		name string
		hash v1.Hash
	}{
		{
			name: "find by manifest index",
			hash: v1.Hash{
				Algorithm: "sha256",
				Hex:       "211a3be9e15e1e4ccd75220aa776d92e06235552351464db2daf043bd30a0ac0",
			},
		},
		{
			name: "find by manifest",
			hash: v1.Hash{
				Algorithm: "sha256",
				Hex:       "c3c447d49bb140a121311afd8d922eef160bfd63872fdb809ae89fdcf27bee50",
			},
		},
		{
			name: "find by config file",
			hash: v1.Hash{
				Algorithm: "sha256",
				Hex:       "412c5a9fed875c1ce63f2dba535353162c9760c07379def9ac87cb0201b532de",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)
			img, err := NewContainerdImage(tt.hash, ContainerdHostFSConfig{
				Platform: v1.Platform{
					Architecture: "amd64",
					OS:           "linux",
				},
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
}

func TestContainerdImageWithIndex(t *testing.T) {
	r := require.New(t)
	img, err := NewContainerdImage(v1.Hash{
		Algorithm: "sha256",
		Hex:       "211a3be9e15e1e4ccd75220aa776d92e06235552351464db2daf043bd30a0ac0",
	},
		ContainerdHostFSConfig{
			Platform: v1.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			ContentDir: "./testdata/containerd_content",
		},
	)
	r.NoError(err)

	index := img.Index()
	r.NotNil(index)
	r.Len(index.Manifests, 2)

	manifest, err := img.Manifest()
	r.NoError(err)
	r.NotNil(manifest)
	r.Len(manifest.Layers, 2)
}
