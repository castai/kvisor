package main

import (
	"context"
	"time"

	"github.com/castai/kvisor/runtime"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

// These should be set via `go build` during a release.
var (
	GitCommit = "undefined"
	GitRef    = "no-ref"
	Version   = "local"
)

func main() {
	log := logrus.New()
	ctx := signals.SetupSignalHandler()
	log.Infof("running castai-kvisor-runtime, version=%s, commit=%s", Version, GitCommit)
	if err := run(ctx, log); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, log *logrus.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
			// Just dummy package doing nothing.
			log.Info("collecting runtime")
			runtime.Collect()
		}
	}
}
