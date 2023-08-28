package config

import (
	"encoding/json"
	"testing"
	"testing/fstest"

	"github.com/castai/kvisor/cmd/imgcollector/image"
	"github.com/stretchr/testify/require"
)

func TestReadImagePullSecret(t *testing.T) {
	r := require.New(t)

	data, err := ReadImagePullSecret(fstest.MapFS{".dockerconfigjson": {
		Data: []byte(`{"auths": {"ghcr.io": {"username": "username", "password": "password", "auth": "token"}}}`),
	}})
	r.NoError(err)

	var cfg image.DockerConfig
	r.NoError(err, json.Unmarshal(data, &cfg))
	auth := cfg.Auths["ghcr.io"]
	r.Equal("username", auth.Username)
	r.Equal("password", auth.Password)
	r.Equal("token", auth.Token)
}
