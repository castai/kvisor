package main

import (
	"context"
	"github.com/castai/sec-agent/cmd/imgcollector/image/hostfs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"runtime"

	"github.com/sirupsen/logrus"

	"github.com/castai/sec-agent/blobscache"
	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/cmd/imgcollector/collector"
	"github.com/castai/sec-agent/cmd/imgcollector/config"
	globalconfig "github.com/castai/sec-agent/config"
)

// These should be set via `go build` during a release.
var (
	GitCommit = "undefined"
	GitRef    = "no-ref"
	Version   = "local"
)

func main() {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatal(err)
	}

	client := castai.NewClient(
		cfg.ApiURL, cfg.ApiKey,
		log,
		cfg.ClusterID,
		"castai-imgcollector",
		globalconfig.SecurityAgentVersion{
			GitCommit: GitCommit,
			GitRef:    GitRef,
			Version:   Version,
		},
	)

	blobsCache := blobscache.NewRemoteBlobsCache(cfg.BlobsCacheURL)

	var h *hostfs.ContainerdHostFSConfig
	if cfg.Mode == config.ModeContainerdHostFS {
		h = &hostfs.ContainerdHostFSConfig{
			Platform: v1.Platform{
				Architecture: runtime.GOARCH,
				OS:           runtime.GOOS,
			},
			ContentDir: config.ContainerdContentDir,
		}
	}
	c := collector.New(log, cfg, client, blobsCache, h)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	log.Infof("collecting artifacts for image '%s(%s)', mode=%s", cfg.ImageName, cfg.ImageID, cfg.Mode)
	err = c.Collect(ctx)
	if err != nil {
		log.Fatalf("image artifacts collection failed: %v", err)
		return
	}
	log.Info("image artifacts collection finished")
}
