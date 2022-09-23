package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sirupsen/logrus"

	"github.com/castai/sec-agent/cmd/imgcollector/config"
	"github.com/castai/sec-agent/cmd/imgcollector/image"

	"gopkg.in/yaml.v3"

	_ "github.com/aquasecurity/trivy/pkg/scanner" // Import all registered analyzers.
)

func New(log logrus.FieldLogger, cfg config.Config) *Collector {
	return &Collector{
		log: log,
		cfg: cfg,
	}
}

type Collector struct {
	log logrus.FieldLogger
	cfg config.Config
}

type ImageInfo struct {
	ID   string
	Name string
}

func (c *Collector) Collect(ctx context.Context) error {
	img, cleanup, err := c.getImage(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	artifact, err := image.NewArtifact(img, c.log, nil, image.ArtifactOption{
		Offline: true,
	})
	if err != nil {
		return err
	}
	res, err := artifact.Inspect(ctx)
	if err != nil {
		return err
	}

	// TODO: Send to cast api. For now dump to file.
	if err := dumpToFile(res); err != nil {
		return err
	}

	return nil
}

func (c *Collector) getImage(ctx context.Context) (image.Image, func(), error) {
	imgRef, err := name.ParseReference(c.cfg.ImageName)
	if err != nil {
		return nil, nil, err
	}

	switch c.cfg.Mode {
	case config.ModeDockerDaemon:
		return image.NewFromDockerDaemon(c.cfg.ImageName, imgRef)
	case config.ModeRemote:
		opts := image.DockerOption{}
		if c.cfg.DockerOptionPath != "" {
			bytes, err := os.ReadFile(c.cfg.DockerOptionPath)
			if err != nil {
				return nil, nil, fmt.Errorf("reading docker options file: %w", err)
			}
			if err := yaml.Unmarshal(bytes, &opts); err != nil {
				return nil, nil, fmt.Errorf("unmarshaling docker options file: %w", err)
			}
		}
		img, err := image.NewFromRemote(ctx, c.cfg.ImageName, opts)
		return img, func() {}, err
	}

	return nil, nil, fmt.Errorf("unknown mode %q", c.cfg.Mode)
}

func dumpToFile(res *image.ArtifactReference) error {
	js, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return os.WriteFile("image-artifacts.json", js, 0755)
}
