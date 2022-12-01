package collector

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/castai/sec-agent/blobscache"
	"github.com/castai/sec-agent/castai"
	an "github.com/castai/sec-agent/cmd/imgcollector/analyzer"
	"github.com/castai/sec-agent/cmd/imgcollector/config"
	"github.com/castai/sec-agent/cmd/imgcollector/image"
	"github.com/castai/sec-agent/cmd/imgcollector/image/hostfs"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"

	// Import all registered analyzers.
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/buildinfo"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/executable"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/c/conan"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/deps"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/nuget"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/binary"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/mod"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/gradle"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/jar"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/pom"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/npm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/pkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/pnpm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/yarn"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/php/composer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/packaging"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pipenv"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/poetry"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/bundler"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/gemspec"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/rust/binary"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/rust/cargo"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/licensing"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/debian"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/mariner"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/release"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/ubuntu"

	// Import modified pkg analyzers.
	_ "github.com/castai/sec-agent/cmd/imgcollector/analyzer/pkg/apk"
	_ "github.com/castai/sec-agent/cmd/imgcollector/analyzer/pkg/dpkg"
	_ "github.com/castai/sec-agent/cmd/imgcollector/analyzer/pkg/rpm"
)

func New(log logrus.FieldLogger, cfg config.Config, client castai.Client, cache blobscache.Client, hostfsConfig *hostfs.ContainerdHostFSConfig) *Collector {
	return &Collector{
		log:          log,
		cfg:          cfg,
		client:       client,
		cache:        cache,
		hostFsConfig: hostfsConfig,
	}
}

type Collector struct {
	log          logrus.FieldLogger
	cfg          config.Config
	client       castai.Client
	cache        blobscache.Client
	hostFsConfig *hostfs.ContainerdHostFSConfig
}

type ImageInfo struct {
	ID   string
	Name string
}

func (c *Collector) collectInstalledBinaries(arRef *image.ArtifactReference) map[string][]string {
	installedFiles := make(map[string][]string)
	for i := range arRef.BlobsInfo {
		for _, customResource := range arRef.BlobsInfo[i].CustomResources {
			if customResource.Type == an.TypeInstalledBinaries {
				data, ok := customResource.Data.(map[string][]string)
				if !ok {
					// after pulling from cache it's map[string]interface{}
					err := mapstructure.Decode(customResource.Data, &data)
					if err != nil {
						c.log.Errorf("failed decoding custom resources %T to map[string][]string: %v", customResource.Data, err)
						continue
					}
				} else {
					c.log.Errorf("could not convert: %T to map[string][]string", customResource.Data)
				}

				for pkg, files := range data {
					installedFiles[pkg] = files
				}
			}
		}
	}

	return installedFiles
}

func (c *Collector) Collect(ctx context.Context) error {
	img, cleanup, err := c.getImage(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	artifact, err := image.NewArtifact(img, c.log, c.cache, image.ArtifactOption{
		Offline: true,
		Slow:    c.cfg.SlowMode, // Slow mode limits concurrency and uses tmp files
		DisabledAnalyzers: []analyzer.Type{
			analyzer.TypeLicenseFile,
			analyzer.TypeDpkgLicense,
		},
	})
	if err != nil {
		return err
	}

	arRef, err := artifact.Inspect(ctx)
	if err != nil {
		return err
	}

	if err := c.client.SendImageMetadata(ctx, &castai.ImageMetadata{
		ImageName:   c.cfg.ImageName,
		ImageID:     c.cfg.ImageID,
		ResourceIDs: strings.Split(c.cfg.ResourceIDs, ","),
		BlobsInfo:   arRef.BlobsInfo,
		ConfigFile:  arRef.ConfigFile,
		OsInfo: &castai.OsInfo{
			ArtifactInfo: arRef.ArtifactInfo,
			OS:           arRef.OsInfo,
		},
		InstalledBinaries: c.collectInstalledBinaries(arRef),
	}); err != nil {
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
	case config.ModeContainerdDaemon:
		return image.NewFromContainerdDaemon(ctx, c.cfg.ImageName)
	case config.ModeDockerDaemon:
		return image.NewFromDockerDaemon(c.cfg.ImageName, imgRef)
	case config.ModeContainerdHostFS:
		return image.NewFromContainerdHostFS(c.cfg.ImageID, c.hostFsConfig)
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
