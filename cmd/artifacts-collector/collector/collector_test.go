package collector

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/castai/sec-agent/cmd/artifacts-collector/config"
)

func TestCollector(t *testing.T) {
	img := os.Getenv("IMG")
	if img == "" {
		t.Skip()
	}

	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	c := New(log, config.Config{
		ImageID:   "todo",
		ImageName: img,
		Timeout:   5 * time.Minute,
		Mode:      config.ModeDockerDaemon,
	})
	err := c.Collect(ctx)
	r.NoError(err)
}
