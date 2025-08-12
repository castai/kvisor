package config

import (
	"encoding/json"
	"testing"
	"testing/fstest"

	"github.com/castai/image-analyzer/image"
	"github.com/stretchr/testify/require"
)

func TestReadImagePullSecret(t *testing.T) {
	r := require.New(t)

	// "username:password" in base64 → "dXNlcm5hbWU6cGFzc3dvcmQ="
	authBase64 := "dXNlcm5hbWU6cGFzc3dvcmQ="

	data, err := ReadImagePullSecret(fstest.MapFS{".dockerconfigjson": {
		Data: []byte(`{"auths": {"ghcr.io": {"username": "username", "password": "password", "auth": "` + authBase64 + `"}}}`),
	}})
	r.NoError(err)

	var cfg image.DockerConfig
	err = json.Unmarshal(data, &cfg)
	r.NoError(err)
	auth := cfg.Auths["ghcr.io"]
	r.Equal("username", auth.Username)
	r.Equal("password", auth.Password)
	r.Equal(authBase64, auth.Auth)
}
