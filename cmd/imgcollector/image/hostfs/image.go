package hostfs

import (
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type Image interface {
	v1.Image
	RepoTags() []string
	RepoDigests() []string
	Index() *v1.IndexManifest
}

// NewImageHash returns image hash from string in format:
// registry.com/repo/image:v0.1.0@sha256:c845d5f019125f896cf552912ab2dc35a6996646975d65878626ac73b89c7b11
func NewImageHash(fqnImageID string) (v1.Hash, error) {
	algStart := 0
	hexStart := 0
	for i, c := range fqnImageID {
		if c == '@' {
			algStart = i + 1
		}
		if c == ':' {
			hexStart = i + 1
		}
	}

	alg := fqnImageID[algStart : hexStart-1]
	if alg == "" {
		return v1.Hash{}, fmt.Errorf("parsing algorithm for image %q", fqnImageID)
	}
	hex := fqnImageID[hexStart:]
	if hex == "" {
		return v1.Hash{}, fmt.Errorf("parsing hex for image %q", fqnImageID)
	}
	return v1.Hash{
		Algorithm: alg,
		Hex:       hex,
	}, nil
}
