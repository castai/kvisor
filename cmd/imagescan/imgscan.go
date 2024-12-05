package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"

	"github.com/castai/image-analyzer/image/hostfs"
	"github.com/castai/kvisor/cmd/imagescan/collector"
	"github.com/castai/kvisor/cmd/imagescan/config"
	"github.com/castai/kvisor/pkg/blobscache"
	"github.com/castai/kvisor/pkg/castai"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewCommand(version string) *cobra.Command {
	// TODO: Switch to pkg/logging.
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	return &cobra.Command{
		Use:   "scan",
		Short: "Run kvisor image scanning",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(cmd.Context(), log, version); err != nil {
				log.Error(err.Error())
				os.Exit(1)
			}
		},
	}
}

func run(ctx context.Context, log *logrus.Logger, version string) error {
	log.Infof("running image scan job, version=%s", version)

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	blobsCache := blobscache.NewRemoteBlobsCacheClient(cfg.BlobsCacheURL)

	ingestClient, err := castai.NewClient(fmt.Sprintf("kvisor-imagescan/%s", version), castai.Config{
		ClusterID:   cfg.CastaiClusterID,
		APIKey:      cfg.CastaiAPIKey,
		APIGrpcAddr: cfg.CastaiAPIGrpcAddr,
		Insecure:    cfg.CastaiGRPCInsecure,
	})
	if err != nil {
		return err
	}
	defer ingestClient.Close()

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
	c := collector.New(log, cfg, ingestClient.GRPC, blobsCache, h)

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
		return fmt.Errorf("image artifacts collection failed: %w", err)
	}
	log.Info("image artifacts collection finished")
	return nil
}

func addPprofHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
