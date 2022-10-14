package config

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Mode string

const (
	ModeRemote           Mode = "remote"
	ModeDockerDaemon     Mode = "docker_daemon"
	ModeContainerdDaemon Mode = "containerd_daemon"
	ModeContainerdHostFS Mode = "containerd_hostfs"
)

const (
	ContainerdContentDir = "/var/lib/containerd/io.containerd.content.v1.content"
)

type Config struct {
	ApiKey           string        `envconfig:"API_KEY" required:"true"`
	ApiURL           string        `envconfig:"API_URL" default:"https://api.cast.ai"`
	ClusterID        string        `envconfig:"CLUSTER_ID" required:"true"`
	ImageID          string        `envconfig:"COLLECTOR_IMAGE_ID" required:"true"`
	ImageName        string        `envconfig:"COLLECTOR_IMAGE_NAME" required:"true"`
	Timeout          time.Duration `envconfig:"COLLECTOR_TIMEOUT" default:"5m"`
	Mode             Mode          `envconfig:"COLLECTOR_MODE" default:"docker_daemon"`
	ResourceIDs      string        `envconfig:"COLLECTOR_RESOURCE_IDS" required:"true"`
	DockerOptionPath string        `envconfig:"COLLECTOR_DOCKER_OPTION_PATH" default:""`
	BlobsCacheURL    string        `envconfig:"COLLECTOR_BLOBS_CACHE_URL" required:"true"`
}

func FromEnv() (Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
