package main

import (
	"context"
	"net/http"
	"net/http/pprof"
	"runtime"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/sirupsen/logrus"

	"github.com/castai/kvisor/blobscache"
	"github.com/castai/kvisor/imgcollector/collector"
	"github.com/castai/kvisor/imgcollector/config"
	"github.com/castai/kvisor/imgcollector/image/hostfs"
)

// These should be set via `go build` during a release.
var (
	GitCommit = "undefined"
	GitRef    = "no-ref"
	Version   = "local"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	log := logger.WithField("component", "imagescan_job")
	log.Infof("running image scan job, version=%s, commit=%s", Version, GitCommit)

	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatal(err)
	}

	blobsCache := blobscache.NewRemoteBlobsCacheClient(cfg.ApiURL)

	var h *hostfs.ContainerdHostFSConfig
	if cfg.Runtime == config.RuntimeContainerd && cfg.Mode == config.ModeHostFS {
		h = &hostfs.ContainerdHostFSConfig{
			Platform: v1.Platform{
				Architecture: runtime.GOARCH,
				OS:           runtime.GOOS,
			},
			ContentDir: config.ContainerdContentDir,
		}
	}
	c := collector.New(log, cfg, blobsCache, h)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if cfg.PprofAddr != "" {
		mux := http.NewServeMux()
		addPprofHandlers(mux)
		go func() {
			if err := http.ListenAndServe(cfg.PprofAddr, mux); err != nil { //nolint:gosec
				log.Warnf("pprof http server failed: %v", err)
			}
		}()
	}

	log.Infof("collecting artifacts for image '%s(%s)', mode=%s", cfg.ImageName, cfg.ImageID, cfg.Mode)
	err = c.Collect(ctx)
	if err != nil {
		log.Fatalf("image artifacts collection failed: %v", err)
		return
	}
	log.Info("image artifacts collection finished")
}

func addPprofHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
