package castai

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	ClusterID   string `json:"clusterID"`
	APIKey      string `json:"-"`
	APIGrpcAddr string `json:"APIGrpcAddr"`
	Insecure    bool   `json:"insecure"`

	CompressionName       string        `json:"compression"`
	DataBatchWriteTimeout time.Duration `json:"dataBatchWriteTimeout"`
}

func NewConfigFromEnv(insecure bool) (Config, error) {
	gRPCAddress, found := os.LookupEnv("CASTAI_API_GRPC_ADDR")
	if !found {
		return Config{}, fmt.Errorf("missing environment variable: CASTAI_API_GRPC_ADDR")
	}

	clusterID, err := lookupConfigVariable("CLUSTER_ID")
	if err != nil {
		return Config{}, err
	}

	apiKey, err := lookupConfigVariable("API_KEY")
	if err != nil {
		return Config{}, err
	}

	return Config{
		APIKey:      apiKey,
		APIGrpcAddr: gRPCAddress,
		ClusterID:   clusterID,
		Insecure:    insecure,
	}, nil
}

func (c Config) Valid() bool {
	return c.ClusterID != "" && c.APIKey != "" && c.APIGrpcAddr != ""
}

func lookupConfigVariable(name string) (string, error) {
	key, found := os.LookupEnv("CASTAI_" + name)
	if found && key != "" {
		return key, nil
	}

	key, found = os.LookupEnv(name)
	if found && key != "" {
		return key, nil
	}

	return "", fmt.Errorf("environment variable missing: please provide either `CAST_%s` or `%s`", name, name)
}
