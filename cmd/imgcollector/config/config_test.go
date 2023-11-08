package config

import (
	"encoding/json"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/castai/kvisor/cmd/imgcollector/image"
)

func TestReadImagePullSecret(t *testing.T) {
	r := require.New(t)

	data, err := ReadImagePullSecret(fstest.MapFS{".dockerconfigjson": {
		Data: []byte(`{"auths": {"ghcr.io": {"username": "username", "password": "password", "auth": "token"}}}`),
	}})
	r.NoError(err)

	var cfg image.DockerConfig
	err = json.Unmarshal(data, &cfg)
	r.NoError(err)
	auth := cfg.Auths["ghcr.io"]
	r.Equal("username", auth.Username)
	r.Equal("password", auth.Password)
	r.Equal("token", auth.Token)
}
