package castai

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ClusterID   string `json:"clusterID"`
	APIKey      string `json:"-"`
	APIURL      string `json:"APIURL"`
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

	cfg := Config{
		APIKey:      apiKey,
		APIGrpcAddr: gRPCAddress,
		ClusterID:   clusterID,
		Insecure:    insecure,
	}

	apiURL, _ := lookupConfigVariable("API_URL")
	if apiURL != "" {
		cfg.APIURL = apiURL
	} else {
		cfg.APIURL = getAPIURL(gRPCAddress)
	}

	return cfg, nil
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

func getAPIURL(grpcAddr string) string {
	envsMapping := map[string]string{
		"kvisor.dev-master.cast.ai:443":  "https://api.dev-master.cast.ai",
		"kvisor.prod-master.cast.ai:443": "https://api.cast.ai",
		"kvisor.prod-eu.cast.ai:443":     "https://api.eu.cast.ai",
	}
	for k, v := range envsMapping {
		if grpcAddr == k {
			return v
		}
	}

	// Other ennvs.
	if strings.HasPrefix(grpcAddr, "api-grpc") {
		return strings.Replace(grpcAddr, "api-grpc", "https://api", 1)
	}
	if strings.HasPrefix(grpcAddr, "grpc") {
		return strings.Replace(grpcAddr, "grpc", "https://api", 1)
	}
	return ""
}
