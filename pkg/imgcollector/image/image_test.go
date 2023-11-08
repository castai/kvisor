package image

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"
)

func TestNamespacedRegistry(t *testing.T) {
	tests := []struct {
		name     string
		ref      name.Reference
		expected string
	}{
		{
			name:     "Github Container Registry",
			ref:      name.MustParseReference("ghcr.io/castai/kvisor/kvisor:latest"),
			expected: "ghcr.io/castai",
		},
		{
			name:     "Gitlab Container Registry",
			ref:      name.MustParseReference("registry.gitlab.com/castai/kvisor/kvisor:latest"),
			expected: "registry.gitlab.com/castai",
		},
		{
			name:     "Docker Container Registry Organization",
			ref:      name.MustParseReference("castai/kvisor"),
			expected: "index.docker.io/castai",
		},
		{
			name:     "Docker Container Registry",
			ref:      name.MustParseReference("kvisor"),
			expected: "index.docker.io/library",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)
			registry := NamespacedRegistry(test.ref)
			r.Equal(test.expected, registry)
		})
	}
}
