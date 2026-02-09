package castai

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ClusterID   string `json:"clusterID"`
	APIKey      string `json:"-"`
	APIBaseURL  string `json:"-"`
	APIGrpcAddr string `json:"APIGrpcAddr"`
	Insecure    bool   `json:"insecure"`

	CompressionName string `json:"compression"`
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
		APIBaseURL:  getAPIBaseURL(gRPCAddress),
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

func getAPIBaseURL(grpcAddr string) string {
	envsMapping := map[string]string{
		"kvisor.dev-master.cast.ai":  "https://api.dev-master.cast.ai",
		"kvisor.prod-master.cast.ai": "https://api.cast.ai",
		"kvisor.prod-eu.cast.ai":     "https://api.eu.cast.ai",
	}
	for k, v := range envsMapping {
		if grpcAddr == k {
			return v
		}
	}

	// Fallback to local dev envs.
	res := strings.ReplaceAll(grpcAddr, "grpc--", "api--")
	res = strings.ReplaceAll(res, "api-grpc--", "api--")
	return res
}
