package config

import (
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	CastaiGRPCInsecure bool   `envconfig:"CASTAI_GRPC_INSECURE"`
	NodeName           string `envconfig:"NODE_NAME"`
	Kubeconfig         string `envconfig:"KUBECONFIG"`
}

func FromEnv() (Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
