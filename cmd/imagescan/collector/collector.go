package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	fanalyzer "github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/cenkalti/backoff/v5"
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
	"github.com/castai/kvisor/cmd/imagescan/config"
	"github.com/castai/kvisor/cmd/imagescan/trivy/golang/analyzer/binary"
)

func init() {
	binary.Register()
}

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
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	img, cleanup, err := c.getImage(ctx)
	if err != nil {
		return fmt.Errorf("getting image: %w", err)
	}
	defer cleanup()

	disabledAnalyzers := []fanalyzer.Type{
		// License
		fanalyzer.TypeLicenseFile,
		fanalyzer.TypeDpkgLicense,

		// Structured config
		fanalyzer.TypeAzureARM,
		fanalyzer.TypeCloudFormation,
		fanalyzer.TypeDockerfile,
		fanalyzer.TypeHelm,
		fanalyzer.TypeKubernetes,
		fanalyzer.TypeTerraform,
		fanalyzer.TypeTerraformPlanJSON,
		fanalyzer.TypeTerraformPlanSnapshot,

		// Java
		fanalyzer.TypeJar, // Jar analyzer needs trivy-java-db, disable it until it is implemented in kvisor
	}

	for _, a := range c.cfg.DisabledAnalyzers {
		if a == "" {
			continue
		}
		disabledAnalyzers = append(disabledAnalyzers, fanalyzer.Type(a))
	}

	artifact, err := analyzer.NewArtifact(img, c.log, c.cache, analyzer.ArtifactOption{
		Offline:           true,
		Parallel:          c.cfg.Parallel,
		DisabledAnalyzers: disabledAnalyzers,
	})
	if err != nil {
		return fmt.Errorf("creating an artifact: %w", err)
	}

	arRef, err := artifact.Inspect(ctx)
	if err != nil {
		return fmt.Errorf("inspecting an artifact: %w", err)
	}

	manifest, err := img.Manifest()
	if err != nil {
		return fmt.Errorf("extracting manifest from an artifact: %w", err)
	}

	digest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("extract manifest digest: %w", err)
	}

	arch := arRef.ConfigFile.Architecture
	// There are rare cases where the Architecture of an image is not set (even though this doesn't appear to be
	// neither OCI nor docker image spec conform). This is not a 100% solution, but should be good enough.
	if strings.TrimSpace(arch) == "" {
		arch = runtime.GOARCH
	}

	metadata := &castaipb.ImageMetadata{
		ImageName:    c.cfg.ImageName,
		ImageId:      c.cfg.ImageID,
		ImageDigest:  digest.String(),
		Architecture: arch,
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
		return fmt.Errorf("marshalling blobs info: %w", err)
	}
	metadata.Packages = packagesBytes

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshalling manifest: %w", err)
	}
	metadata.Manifest = manifestBytes

	configFileBytes, err := json.Marshal(arRef.ConfigFile)
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}
	metadata.ConfigFile = configFileBytes

	if index := img.Index(); index != nil {
		indexBytes, err := json.Marshal(index)
		if err != nil {
			return fmt.Errorf("marshalling index: %w", err)
		}
		metadata.Index = indexBytes
	}

	if _, err := backoff.Retry(ctx, func() (any, error) {
		return nil, c.sendResult(ctx, metadata)
	}, backoff.WithNotify(func(err error, d time.Duration) {
		if err != nil {
			c.log.Errorf("sending result: %v", err)
		}
	})); err != nil {
		return err
	}

	return nil
}

func (c *Collector) getImage(ctx context.Context) (image.ImageWithIndex, func(), error) {
	imgRef, err := name.ParseReference(c.cfg.ImageName)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing image reference: %w", err)
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

			if _, auth, ok := findRegistryAuth(cfg, imgRef, c.log); ok {
				if auth.Username == "" || auth.Password == "" {
					if auth.Token != "" {
						opts.RegistryOptions.RegistryToken = auth.Token
					}
				} else {
					opts.RegistryOptions.Credentials = append(opts.RegistryOptions.Credentials, types.Credential{
						Username: auth.Username,
						Password: auth.Password,
					})
				}
			} else {
				c.log.Infof("image pull secret %q cannot be used to pull %q", c.cfg.ImagePullSecret, imgRef.String())
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
		img, err := image.NewFromRemote(ctx, c.log, c.cfg.ImageName, opts)
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

func findRegistryAuth(cfg image.DockerConfig, imgRef name.Reference, log logrus.FieldLogger) (string, image.RegistryAuth, bool) {
	imageRepo := fmt.Sprintf("%s/%s", imgRef.Context().RegistryStr(), imgRef.Context().RepositoryStr())
	log.Infof("finding registry auth for image %s", imageRepo)

	authKeys := lo.Keys(cfg.Auths)
	sort.Slice(authKeys, func(i, j int) bool { return authKeys[i] > authKeys[j] })
	log.Infof("the following registries were found: %s", authKeys)

	for _, key := range authKeys {
		normalizedKey := normalize(key)
		if strings.HasPrefix(imageRepo, normalizedKey) || strings.HasPrefix(imageRepo, "index."+normalizedKey) {
			log.Infof("selected %s registry auth for image %s", key, imageRepo)
			return key, cfg.Auths[key], true
		}
	}

	return "", image.RegistryAuth{}, false
}

var (
	dockerHubMatcherRegex = regexp.MustCompile("(/v1|/v2)$")
)

// normalize registryKey from the pull secret to follow the resolved image repo format
func normalize(registryKey string) string {
	trimmed := strings.TrimPrefix(registryKey, "http://")
	trimmed = strings.TrimPrefix(trimmed, "https://")
	trimmed = strings.TrimSuffix(trimmed, "/")
	if strings.HasPrefix(trimmed, "docker.io") || strings.HasPrefix(trimmed, "index.docker.io") {
		trimmed = dockerHubMatcherRegex.ReplaceAllString(trimmed, "")
	}
	return trimmed
}
