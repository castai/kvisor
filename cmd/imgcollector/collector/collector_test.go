package collector

import (
	"context"
	"github.com/golang/mock/gomock"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/castai/sec-agent/blobscache"
	mock_blobcache "github.com/castai/sec-agent/blobscache/mock"
	mock_castai "github.com/castai/sec-agent/castai/mock"
	"github.com/castai/sec-agent/cmd/imgcollector/config"
)

func TestCollector(t *testing.T) {
	imgName := os.Getenv("IMG_NAME")
	if imgName == "" {
		t.Skip()
	}

	imgID := os.Getenv("IMG_ID")
	if imgID == "" {
		t.Skip()
	}

	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	ctrl := gomock.NewController(t)
	mockClient := mock_castai.NewMockClient(ctrl)
	mockCache := mock_blobcache.NewMockClient(ctrl)

	c := New(log, config.Config{
		ImageID:   imgID,
		ImageName: imgName,
		Timeout:   5 * time.Minute,
		Mode:      config.ModeContainerdBlob,
	}, mockClient, mockCache)

	mockCache.EXPECT().GetBlob(gomock.Any(), gomock.Any()).Return(nil, blobscache.ErrCacheNotFound).AnyTimes()
	mockCache.EXPECT().PutBlob(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockClient.EXPECT().SendImageMetadata(gomock.Any(), gomock.Any())
	err := c.Collect(ctx)
	r.NoError(err)
}
