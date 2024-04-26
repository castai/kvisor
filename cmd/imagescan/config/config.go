package config

import (
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Mode string

const (
	ModeRemote Mode = "remote"
	ModeDaemon Mode = "daemon"
	ModeHostFS Mode = "hostfs"
	// ModeTarArchive is currently used only to test local tar archive images.
	// Loading image from docker daemon on macOS is super slow.
	ModeTarArchive Mode = "tar"
)

type Runtime string

const (
	RuntimeDocker     = "docker"
	RuntimeContainerd = "containerd"
)

const (
	ContainerdContentDir = "/var/lib/containerd/io.containerd.content.v1.content"
	SecretMountPath      = "/secret"
)

type Config struct {
	CastaiClusterID   string `envconfig:"CASTAI_CLUSTER_ID" required:"true"`
	CastaiAPIGrpcAddr string `envconfig:"CASTAI_API_GRPC_ADDR" required:"true"`
	// The api key is required, but we support two differnt ways of setting it.
	CastaiAPIKey       string `envconfig:"CASTAI_API_KEY"`
	CastaiGRPCInsecure bool   `envconfig:"CASTAI_GRPC_INSECURE"`

	BlobsCacheURL     string        `envconfig:"COLLECTOR_BLOBS_CACHE_URL"`
	ImageID           string        `envconfig:"COLLECTOR_IMAGE_ID" required:"true"`
	ImageName         string        `envconfig:"COLLECTOR_IMAGE_NAME" required:"true"`
	ImageArchitecture string        `envconfig:"COLLECTOR_IMAGE_ARCHITECTURE" required:"true"`
	ImageOS           string        `envconfig:"COLLECTOR_IMAGE_OS" required:"true"`
	ImagePullSecret   string        `envconfig:"COLLECTOR_PULL_SECRET" default:""`
	Timeout           time.Duration `envconfig:"COLLECTOR_TIMEOUT" default:"5m"`
	Mode              Mode          `envconfig:"COLLECTOR_MODE"`
	Runtime           Runtime       `envconfig:"COLLECTOR_RUNTIME" required:"true"`
	ResourceIDs       string        `envconfig:"COLLECTOR_RESOURCE_IDS" required:"true"`
	DockerOptionPath  string        `envconfig:"COLLECTOR_DOCKER_OPTION_PATH" default:""`
	PprofAddr         string        `envconfig:"COLLECTOR_PPROF_ADDR" default:""`
	Parallel          int           `envconfig:"COLLECTOR_PARALLEL" default:"1"`
	// ImageLocalTarPath is used only with ModeTarArchive for local dev.
	ImageLocalTarPath string
}

func FromEnv() (Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return Config{}, err
	}

	if cfg.CastaiAPIKey == "" {
		// fall back to non `CASTAI` prefix env variable
		if apiKey, found := os.LookupEnv("API_KEY"); found {
			cfg.CastaiAPIKey = apiKey
		} else {
			return Config{}, errors.New("required environment variable not set: CASTAI_API_KEY or API_KEY are missing")
		}
	}

	return cfg, nil
}

// ReadImagePullSecret explicitly mounted at mountPath.
func ReadImagePullSecret(mount fs.FS) ([]byte, error) {
	/*
		apiVersion: v1
		kind: Secret
		type: kubernetes.io/dockerconfigjson
		data:
			.dockerconfigjson: "<base64 encoded ~/.docker/config.json>"
	*/
	// When mounted, data keys become plain text files in the filesystem.
	return fs.ReadFile(mount, ".dockerconfigjson")
}
