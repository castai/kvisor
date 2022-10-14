package collector

import (
	"context"
	"os"
	"path"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	mock_blobcache "github.com/castai/sec-agent/blobscache/mock"
	mock_castai "github.com/castai/sec-agent/castai/mock"
	"github.com/castai/sec-agent/cmd/imgcollector/config"
	"github.com/castai/sec-agent/cmd/imgcollector/image/hostfs"
)

func TestCollector(t *testing.T) {
	imgName := "notused"
	imgID := "1ff6c18fbef2045af6b9c16bf034cc421a29027b800e4f9b68ae9b1cb3e9ae07"

	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	ctrl := gomock.NewController(t)
	mockClient := mock_castai.NewMockClient(ctrl)
	mockCache := mock_blobcache.MockClient{}

	cwd, _ := os.Getwd()
	p := path.Join(cwd, "..", "image/hostfs/testdata/amd64-linux/io.containerd.content.v1.content")

	c := New(log, config.Config{
		ImageID:   imgID,
		ImageName: imgName,
		Timeout:   5 * time.Minute,
		Mode:      config.ModeContainerdHostFS,
	}, mockClient, mockCache, &hostfs.ContainerdHostFSConfig{
		Platform: v1.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		ContentDir: p,
	})

	mockClient.EXPECT().SendImageMetadata(gomock.Any(), gomock.Any())
	err := c.Collect(ctx)
	r.NoError(err)
}
