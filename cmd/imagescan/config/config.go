package config

import (
	"io/fs"
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
	CastaiGRPCInsecure bool `envconfig:"CASTAI_GRPC_INSECURE"`

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
	DisabledAnalyzers []string      `envconfig:"COLLECTOR_DISABLED_ANALYZERS" default:""`
	// ImageLocalTarPath is used only with ModeTarArchive for local dev.
	ImageLocalTarPath string
}

func FromEnv() (Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return Config{}, err
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
