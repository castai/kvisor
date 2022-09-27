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
	// TODO: Implement 'host_mount` mode to inspect mounted layers.
)

type Config struct {
	ImageID          string        `envconfig:"ARTIFACTS_COLLECTOR_IMAGE_ID" required:"true"`
	ImageName        string        `envconfig:"ARTIFACTS_COLLECTOR_IMAGE_NAME" required:"true"`
	Timeout          time.Duration `envconfig:"ARTIFACTS_COLLECTOR_TIMEOUT" default:"5m"`
	Mode             Mode          `envconfig:"ARTIFACTS_COLLECTOR_MODE" default:"docker_daemon"`
	APIUrl           string        `envconfig:"ARTIFACTS_COLLECTOR_API_URL" default:"https://api.cast.ai"`
	DockerOptionPath string        `envconfig:"ARTIFACTS_COLLECTOR_DOCKER_OPTION_PATH" default:""`
}

func FromEnv() (Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
