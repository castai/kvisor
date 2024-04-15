package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	fanalyzer "github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"

	analyzer "github.com/castai/image-analyzer"
	"github.com/castai/image-analyzer/image"
	"github.com/castai/image-analyzer/image/hostfs"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/imagescan/config"
)

type ingestClient interface {
	ImageMetadataIngest(ctx context.Context, in *castaipb.ImageMetadata, opts ...grpc.CallOption) (*castaipb.ImageMetadataIngestResponse, error)
}

func New(
	log logrus.FieldLogger,
	cfg config.Config,
	ingestClient ingestClient,
	cache analyzer.CacheClient,
	hostfsConfig *hostfs.ContainerdHostFSConfig,
) *Collector {
	return &Collector{
		log:          log,
		cfg:          cfg,
		ingestClient: ingestClient,
		cache:        cache,
		hostFsConfig: hostfsConfig,
	}
}

type Collector struct {
	log          logrus.FieldLogger
	cfg          config.Config
	ingestClient ingestClient
	cache        analyzer.CacheClient
	hostFsConfig *hostfs.ContainerdHostFSConfig
}

type ImageInfo struct {
	ID   string
	Name string
}

func (c *Collector) Collect(ctx context.Context) error {
	img, cleanup, err := c.getImage(ctx)
	if err != nil {
		return fmt.Errorf("getting image: %w", err)
	}
	defer cleanup()

	artifact, err := analyzer.NewArtifact(img, c.log, c.cache, analyzer.ArtifactOption{
		Offline:  true,
		Parallel: c.cfg.Parallel,
		DisabledAnalyzers: []fanalyzer.Type{
			fanalyzer.TypeLicenseFile,
			fanalyzer.TypeDpkgLicense,
			fanalyzer.TypeHelm,
		},
	})
	if err != nil {
		return err
	}

	arRef, err := artifact.Inspect(ctx)
	if err != nil {
		return err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return fmt.Errorf("extract manifest: %w", err)
	}

	digest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("extract manifest digest: %w", err)
	}

	metadata := &castaipb.ImageMetadata{
		ImageName:    c.cfg.ImageName,
		ImageId:      c.cfg.ImageID,
		ImageDigest:  digest.String(),
		Architecture: c.cfg.ImageArchitecture,
		ResourceIds:  strings.Split(c.cfg.ResourceIDs, ","),
	}
	if arRef.OsInfo != nil {
		metadata.OsName = arRef.OsInfo.Name
	}
	if arRef.ArtifactInfo != nil {
		metadata.CreatedAt = timestamppb.New(arRef.ArtifactInfo.Created)
	}
	packagesBytes, err := json.Marshal(arRef.BlobsInfo)
	if err != nil {
		return err
	}
	metadata.Packages = packagesBytes

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	metadata.Manifest = manifestBytes

	configFileBytes, err := json.Marshal(arRef.ConfigFile)
	if err != nil {
		return err
	}
	metadata.ConfigFile = configFileBytes

	if index := img.Index(); index != nil {
		indexBytes, err := json.Marshal(index)
		if err != nil {
			return err
		}
		metadata.Index = indexBytes
	}

	if err := backoff.RetryNotify(func() error {
		return c.sendResult(ctx, metadata)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 3), func(err error, duration time.Duration) {
		if err != nil {
			c.log.Errorf("sending result: %v", err)
		}
	}); err != nil {
		return err
	}

	return nil
}

func (c *Collector) getImage(ctx context.Context) (image.ImageWithIndex, func(), error) {
	imgRef, err := name.ParseReference(c.cfg.ImageName)
	if err != nil {
		return nil, nil, err
	}
	if c.cfg.Mode == config.ModeRemote {
		opts := types.ImageOptions{}
		if c.cfg.ImagePullSecret != "" {
			configData, err := config.ReadImagePullSecret(os.DirFS(config.SecretMountPath))
			if err != nil {
				return nil, nil, fmt.Errorf("reading image pull secret: %w", err)
			}
			cfg := image.DockerConfig{}
			if err := json.Unmarshal(configData, &cfg); err != nil {
				return nil, nil, fmt.Errorf("parsing image pull secret: %w", err)
			}

			if authKey, auth, ok := findRegistryAuth(cfg, imgRef); ok {
				c.log.Infof("using registry auth, key=%s", authKey)
				opts.RegistryOptions.Credentials = append(opts.RegistryOptions.Credentials, types.Credential{
					Username: auth.Username,
					Password: auth.Password,
				})
				opts.RegistryOptions.RegistryToken = auth.Token
			}
		} else if c.cfg.DockerOptionPath != "" {
			optsData, err := os.ReadFile(c.cfg.DockerOptionPath)
			if err != nil {
				return nil, nil, fmt.Errorf("reading docker options file: %w", err)
			}
			if err := yaml.Unmarshal(optsData, &opts); err != nil {
				return nil, nil, fmt.Errorf("unmarshaling docker options file: %w", err)
			}
		}
		if c.cfg.ImageArchitecture != "" && c.cfg.ImageOS != "" {
			opts.RegistryOptions.Platform = types.Platform{
				Platform: &v1.Platform{
					Architecture: c.cfg.ImageArchitecture,
					OS:           c.cfg.ImageOS,
				},
			}
		}
		img, err := image.NewFromRemote(ctx, c.cfg.ImageName, opts)
		return img, func() {}, err
	}

	if c.cfg.Runtime == config.RuntimeContainerd {
		if c.cfg.Mode == config.ModeDaemon {
			return image.NewFromContainerdDaemon(ctx, c.cfg.ImageName)
		}
		if c.cfg.Mode == config.ModeHostFS {
			return image.NewFromContainerdHostFS(c.cfg.ImageID, *c.hostFsConfig)
		}
	}

	if c.cfg.Runtime == config.RuntimeDocker {
		if c.cfg.Mode == config.ModeTarArchive {
			return image.NewFromDockerDaemonTarFile(c.cfg.ImageName, c.cfg.ImageLocalTarPath, imgRef)
		}
		if c.cfg.Mode == config.ModeDaemon {
			return image.NewFromDockerDaemon(c.cfg.ImageName, imgRef)
		}
	}

	return nil, nil, fmt.Errorf("unknown mode %q", c.cfg.Mode)
}

func (c *Collector) sendResult(ctx context.Context, imageMetadata *castaipb.ImageMetadata) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := c.ingestClient.ImageMetadataIngest(ctx, imageMetadata); err != nil {
		return err
	}
	return nil
}

func findRegistryAuth(cfg image.DockerConfig, imgRef name.Reference) (string, image.RegistryAuth, bool) {
	imageRepo := fmt.Sprintf("%s/%s", imgRef.Context().RegistryStr(), imgRef.Context().RepositoryStr())

	authKeys := lo.Keys(cfg.Auths)
	sort.Strings(authKeys)

	for _, key := range authKeys {
		// User can provide registries with protocol which we don't care about while comparing with image name.
		prefix := strings.TrimPrefix(key, "http://")
		prefix = strings.TrimPrefix(prefix, "https://")
		if strings.HasPrefix(imageRepo, prefix) {
			return key, cfg.Auths[key], true
		}
	}
	return "", image.RegistryAuth{}, false
}
