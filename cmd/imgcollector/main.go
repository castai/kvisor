package main

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/castai/sec-agent/cmd/imgcollector/collector"
	"github.com/castai/sec-agent/cmd/imgcollector/config"
)

func main() {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatal(err)
	}

	c := collector.New(log, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	log.Infof("collecting artifacts for image '%s(%s)'", cfg.ImageName, cfg.ImageID)
	err = c.Collect(ctx)
	if err != nil {
		log.Fatalf("image artifacts collection failed: %v", err)
		return
	}
	log.Info("image artifacts collection finished")
}
