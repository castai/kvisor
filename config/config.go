package config

import (
	"fmt"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Config struct {
	PodIP             string        `envconfig:"POD_IP" yaml:"podIP"`
	PodNamespace      string        `envconfig:"POD_NAMESPACE" yaml:"podNamespace"`
	KubeClient        KubeClient    `envconfig:"KUBE_CLIENT" yaml:"kubeClient"`
	Log               Log           `envconfig:"LOG" yaml:"log"`
	API               API           `envconfig:"API" yaml:"api"`
	PprofPort         int           `envconfig:"PPROF_PORT" yaml:"pprofPort"`
	Provider          string        `envconfig:"PROVIDER" yaml:"provider"`
	DeltaSyncInterval time.Duration `envconfig:"DELTA_SYNC_INTERVAL" yaml:"deltaSyncInterval"`
	ImageScan         ImageScan     `envconfig:"IMAGE_SCAN" yaml:"imageScan"`
	Linter            Linter        `envconfig:"LINTER" yaml:"linter"`
	KubeBench         KubeBench     `envconfig:"KUBE_BENCH" yaml:"kubeBench"`
	CloudScan         CloudScan     `envconfig:"CLOUD_SCAN" yaml:"cloudScan"`
}

type CloudScan struct {
	Enabled      bool          `envconfig:"ENABLED" yaml:"enabled"`
	ScanInterval time.Duration `envconfig:"SCAN_INTERVAL" yaml:"scanInterval"`
	GKE          *CloudScanGKE `envconfig:"GKE" yaml:"gke"`
	EKS          *CloudScanEKS `envconfig:"EKS" yaml:"eks"`
}

type CloudScanGKE struct {
	ClusterName        string `envconfig:"CLUSTER_NAME" yaml:"clusterName"`
	CredentialsFile    string `envconfig:"CREDENTIALS_FILE" yaml:"credentialsFile"`
	ServiceAccountName string `envconfig:"SERVICE_ACCOUNT_NAME" yaml:"serviceAccountName"`
}

type CloudScanEKS struct {
	ClusterName string `envconfig:"CLUSTER_NAME" yaml:"clusterName"`
}

type ImageScan struct {
	Enabled            bool           `envconfig:"ENABLED" yaml:"enabled"`
	ScanInterval       time.Duration  `envconfig:"SCAN_INTERVAL" yaml:"scanInterval"`
	ScanTimeout        time.Duration  `envconfig:"SCAN_TIMEOUT" yaml:"scanTimeout"`
	MaxConcurrentScans int64          `envconfig:"MAX_CONCURRENT_SCANS" yaml:"maxConcurrentScans"`
	Image              ImageScanImage `envconfig:"IMAGE" yaml:"image"`
	Mode               string         `envconfig:"MODE" yaml:"mode"`
	DockerOptionsPath  string         `envconfig:"DOCKER_OPTIONS_PATH" yaml:"dockerOptionsPath"`
	BlobsCachePort     int            `envconfig:"BLOBS_CACHE_PORT" yaml:"blobsCachePort"`
	CPURequest         string         `envconfig:"CPU_REQUEST" yaml:"cpuRequest"`
	CPULimit           string         `envconfig:"CPU_LIMIT" yaml:"cpuLimit"`
	MemoryRequest      string         `envconfig:"MEMORY_REQUEST" yaml:"memoryRequest"`
	MemoryLimit        string         `envconfig:"MEMORY_LIMIT" yaml:"memoryLimit"`
	Force              bool           `envconfig:"FORCE" yaml:"force"`
}

type ImageScanImage struct {
	Name       string `envconfig:"NAME" yaml:"name"`
	PullPolicy string `envconfig:"PULL_POLICY" yaml:"pullPolicy"`
}

type Linter struct {
	Enabled bool `envconfig:"ENABLED" yaml:"enabled"`
}

type KubeBench struct {
	Enabled      bool          `envconfig:"ENABLED" yaml:"enabled"`
	ScanInterval time.Duration `envconfig:"SCAN_INTERVAL" yaml:"scanInterval"`
}

type KubeClient struct {
	// K8S client rate limiter allows bursts of up to 'burst' to exceed the QPS, while still maintaining a
	// smoothed qps rate of 'qps'.
	// The bucket is initially filled with 'burst' tokens, and refills at a rate of 'qps'.
	// The maximum number of tokens in the bucket is capped at 'burst'.
	QPS   int `envconfig:"QPS" yaml:"qps"`
	Burst int `envconfig:"BURST" yaml:"burst"`
	// Custom kubeconfig path.
	KubeConfigPath string `envconfig:"KUBECONFIG" yaml:"kubeconfig"`
}

type Log struct {
	Level string `envconfig:"LEVEL" yaml:"level"`
}

type API struct {
	Key       string `envconfig:"KEY" yaml:"key"`
	URL       string `envconfig:"URL" yaml:"url"`
	ClusterID string `envconfig:"CLUSTER_ID" yaml:"clusterID"`
}

func Load(configPath string) (Config, error) {
	var cfg Config
	// Load config from yaml file if specified.
	if configPath != "" {
		configBytes, err := os.ReadFile(configPath)
		if err != nil {
			return Config{}, err
		}
		if err := yaml.Unmarshal(configBytes, &cfg); err != nil {
			return Config{}, err
		}
	}
	// Override with evn variables (if any).
	if err := envconfig.Process("", &cfg); err != nil {
		return Config{}, err
	}

	// Validate and set defaults.
	if cfg.API.URL == "" {
		return cfg, required("API_URL")
	}
	if cfg.API.Key == "" {
		return cfg, required("API_KEY")
	}
	if cfg.API.ClusterID == "" {
		return cfg, required("CLUSTER_ID")
	}
	if cfg.KubeClient.QPS == 0 {
		cfg.KubeClient.QPS = 25
	}
	if cfg.KubeClient.Burst == 0 {
		cfg.KubeClient.Burst = 150
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = logrus.DebugLevel.String()
	} else {
		if _, err := logrus.ParseLevel(cfg.Log.Level); err != nil {
			return Config{}, err
		}
	}
	if cfg.ImageScan.Enabled {
		if cfg.ImageScan.Image.Name == "" {
			return cfg, required("IMAGE_SCAN_IMAGE_NAME")
		}
		if cfg.ImageScan.Image.PullPolicy == "" {
			cfg.ImageScan.Image.PullPolicy = "IfNotPresent"
		}
		if cfg.ImageScan.DockerOptionsPath == "" {
			cfg.ImageScan.DockerOptionsPath = "/etc/docker/config.json"
		}
		if cfg.ImageScan.MaxConcurrentScans == 0 {
			cfg.ImageScan.MaxConcurrentScans = 3
		}
		if cfg.ImageScan.BlobsCachePort == 0 {
			cfg.ImageScan.BlobsCachePort = 8080
		}
		if cfg.ImageScan.ScanInterval == 0 {
			cfg.ImageScan.ScanInterval = 15 * time.Second
		}
		if cfg.ImageScan.ScanTimeout == 0 {
			cfg.ImageScan.ScanTimeout = 10 * time.Minute
		}
		if cfg.ImageScan.CPURequest == "" {
			cfg.ImageScan.CPURequest = "100m"
		}
		if cfg.ImageScan.CPULimit == "" {
			cfg.ImageScan.CPULimit = "4"
		}
		if cfg.ImageScan.MemoryRequest == "" {
			cfg.ImageScan.MemoryRequest = "200Mi"
		}
		if cfg.ImageScan.MemoryLimit == "" {
			cfg.ImageScan.MemoryLimit = "2Gi"
		}
	}
	if cfg.CloudScan.Enabled {
		if cfg.CloudScan.ScanInterval == 0 {
			cfg.CloudScan.ScanInterval = 1 * time.Hour
		}
	}
	if cfg.KubeBench.Enabled {
		if cfg.KubeBench.ScanInterval == 0 {
			cfg.KubeBench.ScanInterval = 15 * time.Second
		}
	}

	if cfg.PprofPort == 0 {
		cfg.PprofPort = 6060
	}
	if cfg.Provider == "" {
		cfg.Provider = "on-premise"
	}
	if cfg.DeltaSyncInterval == 0 {
		cfg.DeltaSyncInterval = 15 * time.Second
	}

	return cfg, nil
}

func required(variable string) error {
	return fmt.Errorf("env variable %s is required", variable)
}
