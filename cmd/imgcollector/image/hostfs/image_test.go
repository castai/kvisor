package hostfs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewImageHash(t *testing.T) {
	r := require.New(t)

	h, err := NewImageHash("sha256:4c1e997385b8fb4ad4d1d3c7e5af7ff3f882e94d07cf5b78de9e889bc60830e6")
	r.NoError(err)
	r.Equal("sha256", h.Algorithm)
	r.Equal("4c1e997385b8fb4ad4d1d3c7e5af7ff3f882e94d07cf5b78de9e889bc60830e6", h.Hex)

	h, err = NewImageHash("my/image:v0.1.1@sha256:4c1e997385b8fb4ad4d1d3c7e5af7ff3f882e94d07cf5b78de9e889bc60830e6")
	r.NoError(err)
	r.Equal("sha256", h.Algorithm)
	r.Equal("4c1e997385b8fb4ad4d1d3c7e5af7ff3f882e94d07cf5b78de9e889bc60830e6", h.Hex)

	h, err = NewImageHash(":4c1e997385b8fb4ad4d1d3c7e5af7ff3f882e94d07cf5b78de9e889bc60830e6")
	r.ErrorContains(err, "parsing algorithm for image")

	h, err = NewImageHash("sha256:")
	r.ErrorContains(err, "parsing hex for image")
}
