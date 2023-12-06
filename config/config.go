package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Config struct {
	PodIP             string            `envconfig:"POD_IP" yaml:"podIP"`
	PodNamespace      string            `envconfig:"POD_NAMESPACE" yaml:"podNamespace"`
	ServiceName       string            `envconfig:"SERVICE_NAME" yaml:"serviceName"`
	ServicePort       int               `envconfig:"SERVICE_PORT" yaml:"servicePort"`
	CertsDir          string            `envconfig:"CERTS_DIR" yaml:"certsDir"`
	CertsSecret       string            `envconfig:"CERTS_SECRET" yaml:"certsSecret"`
	LeaderElection    bool              `envconfig:"LEADER_ELECTION" yaml:"leaderElection"`
	PolicyEnforcement PolicyEnforcement `envconfig:"POLICY_ENFORCEMENT" yaml:"policyEnforcement"`
	KubeClient        KubeClient        `envconfig:"KUBE_CLIENT" yaml:"kubeClient"`
	Log               Log               `envconfig:"LOG" yaml:"log"`
	API               API               `envconfig:"API" yaml:"api"`
	HTTPPort          int               `envconfig:"HTTP_PORT" yaml:"httpPort"`
	StatusPort        int               `envconfig:"STATUS_PORT" yaml:"statusPort"`
	Provider          string            `envconfig:"PROVIDER" yaml:"provider"`
	DeltaSyncInterval time.Duration     `envconfig:"DELTA_SYNC_INTERVAL" yaml:"deltaSyncInterval"`
	ImageScan         ImageScan         `envconfig:"IMAGE_SCAN" yaml:"imageScan"`
	Linter            Linter            `envconfig:"LINTER" yaml:"linter"`
	KubeBench         KubeBench         `envconfig:"KUBE_BENCH" yaml:"kubeBench"`
	CloudScan         CloudScan         `envconfig:"CLOUD_SCAN" yaml:"cloudScan"`
	Telemetry         Telemetry         `envconfig:"TELEMETRY" yaml:"telemetry"`
}

type PolicyEnforcement struct {
	Enabled     bool    `envconfig:"POLICY_ENFORCEMENT_ENABLED" yaml:"enabled"`
	WebhookName string  `envconfig:"POLICY_ENFORCEMENT_WEBHOOK_NAME" yaml:"webhookName"`
	Bundles     Bundles `envconfig:"POLICY_ENFORCEMENT_BUNDLES" yaml:"bundles"`
}

type Bundles []string

func (b *Bundles) Decode(input string) error {
	result := strings.Split(input, ",")
	*b = result
	return nil
}

type CloudScan struct {
	Enabled      bool          `envconfig:"CLOUD_SCAN_ENABLED" yaml:"enabled"`
	ScanInterval time.Duration `envconfig:"CLOUD_SCAN_SCAN_INTERVAL" yaml:"scanInterval"`
	GKE          *CloudScanGKE `envconfig:"CLOUD_SCAN_GKE" yaml:"gke"`
	EKS          *CloudScanEKS `envconfig:"CLOUD_SCAN_EKS" yaml:"eks"`
}

type CloudScanGKE struct {
	ClusterName        string `envconfig:"CLOUD_SCAN_GKE_CLUSTER_NAME" yaml:"clusterName"`
	CredentialsFile    string `envconfig:"CLOUD_SCAN_GKE_CREDENTIALS_FILE" yaml:"credentialsFile"`
	ServiceAccountName string `envconfig:"CLOUD_SCAN_GKE_SERVICE_ACCOUNT_NAME" yaml:"serviceAccountName"`
}

type CloudScanEKS struct {
	ClusterName string `envconfig:"CLOUD_SCAN_EKS_CLUSTER_NAME" yaml:"clusterName"`
}

type ImageScan struct {
	Enabled            bool           `envconfig:"IMAGE_SCAN_ENABLED" yaml:"enabled"`
	ScanInterval       time.Duration  `envconfig:"IMAGE_SCAN_SCAN_INTERVAL" yaml:"scanInterval"`
	ScanTimeout        time.Duration  `envconfig:"IMAGE_SCAN_SCAN_TIMEOUT" yaml:"scanTimeout"`
	MaxConcurrentScans int64          `envconfig:"IMAGE_SCAN_MAX_CONCURRENT_SCANS" yaml:"maxConcurrentScans"`
	Image              ImageScanImage `envconfig:"IMAGE_SCAN_IMAGE" yaml:"image"`
	Mode               string         `envconfig:"IMAGE_SCAN_MODE" yaml:"mode"`
	APIUrl             string         `envconfig:"IMAGE_SCAN_API_URL" yaml:"apiUrl"`
	DockerOptionsPath  string         `envconfig:"IMAGE_SCAN_DOCKER_OPTIONS_PATH" yaml:"dockerOptionsPath"`
	CPURequest         string         `envconfig:"IMAGE_SCAN_CPU_REQUEST" yaml:"cpuRequest"`
	CPULimit           string         `envconfig:"IMAGE_SCAN_CPU_LIMIT" yaml:"cpuLimit"`
	MemoryRequest      string         `envconfig:"IMAGE_SCAN_MEMORY_REQUEST" yaml:"memoryRequest"`
	MemoryLimit        string         `envconfig:"IMAGE_SCAN_MEMORY_LIMIT" yaml:"memoryLimit"`
	ProfileEnabled     bool           `envconfig:"IMAGE_SCAN_PROFILE_ENABLED" yaml:"profileEnabled"`
	PhlareEnabled      bool           `envconfig:"IMAGE_SCAN_PHLARE_ENABLED" yaml:"phlareEnabled"`
	PullSecret         string         `envconfig:"IMAGE_SCAN_PULL_SECRET" yaml:"pullSecret"`
	InitDelay          time.Duration  `envconfig:"IMAGE_SCAN_INIT_DELAY" yaml:"initDelay"`
	ServiceAccountName string         `envconfig:"IMAGE_SCAN_SERVICE_ACCOUNT_NAME" yaml:"serviceAccountName"`
}

type ImageScanImage struct {
	Name       string `envconfig:"IMAGE_SCAN_IMAGE_NAME" yaml:"name"`
	PullPolicy string `envconfig:"IMAGE_SCAN_IMAGE_PULL_POLICY" yaml:"pullPolicy"`
}

type Linter struct {
	Enabled      bool          `envconfig:"LINTER_ENABLED" yaml:"enabled"`
	ScanInterval time.Duration `envconfig:"LINTER_SCAN_INTERVAL" yaml:"scanInterval"`
}

type KubeBench struct {
	Enabled      bool           `envconfig:"KUBE_BENCH_ENABLED" yaml:"enabled"`
	Force        bool           `envconfig:"KUBE_BENCH_FORCE" yaml:"force"`
	ScanInterval time.Duration  `envconfig:"KUBE_BENCH_SCAN_INTERVAL" yaml:"scanInterval"`
	Image        KubeBenchImage `envconfig:"KUBE_BENCH_IMAGE" yaml:"image"`
}

type KubeBenchImage struct {
	Name       string `envconfig:"KUBE_BENCH_IMAGE_NAME" yaml:"name"`
	PullPolicy string `envconfig:"KUBE_BENCH_IMAGE_PULL_POLICY" yaml:"pullPolicy"`
}

type KubeClient struct {
	// K8S client rate limiter allows bursts of up to 'burst' to exceed the QPS, while still maintaining a
	// smoothed qps rate of 'qps'.
	// The bucket is initially filled with 'burst' tokens, and refills at a rate of 'qps'.
	// The maximum number of tokens in the bucket is capped at 'burst'.
	QPS   int `envconfig:"KUBE_CLIENT_QPS" yaml:"qps"`
	Burst int `envconfig:"KUBE_CLIENT_BURST" yaml:"burst"`
	// Custom kubeconfig path.
	KubeConfigPath string `envconfig:"KUBE_CLIENT_KUBECONFIG" yaml:"kubeconfig"`
	UseProtobuf    bool   `envconfig:"KUBE_CLIENT_USE_PROTOBUF" yaml:"useProtobuf"`
}

type Log struct {
	Level string `envconfig:"LOG_LEVEL" yaml:"level"`
}

type API struct {
	Key       string `envconfig:"API_KEY" yaml:"key"`
	URL       string `envconfig:"API_URL" yaml:"url"`
	ClusterID string `envconfig:"API_CLUSTER_ID" yaml:"clusterID"`
}

type Telemetry struct {
	Interval time.Duration `envconfig:"TELEMETRY_INTERVAL" yaml:"interval"`
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
		if cfg.ImageScan.MaxConcurrentScans == 0 {
			cfg.ImageScan.MaxConcurrentScans = 3
		}
		if cfg.ImageScan.ScanInterval == 0 {
			cfg.ImageScan.ScanInterval = 15 * time.Second
		}
		if cfg.ImageScan.ScanTimeout == 0 {
			cfg.ImageScan.ScanTimeout = 10 * time.Minute
		}
		if cfg.ImageScan.CPULimit == "" {
			cfg.ImageScan.CPULimit = "4"
		}
		if cfg.ImageScan.CPURequest == "" {
			cfg.ImageScan.CPURequest = "1m"
		}
		if cfg.ImageScan.MemoryLimit == "" {
			cfg.ImageScan.MemoryLimit = "2Gi"
		}
		if cfg.ImageScan.MemoryRequest == "" {
			cfg.ImageScan.MemoryRequest = "1Mi"
		}
		if cfg.ImageScan.APIUrl == "" {
			cfg.ImageScan.APIUrl = "http://kvisor.castai-agent.svc.cluster.local.:6060"
		}
		if cfg.ImageScan.InitDelay == 0 {
			cfg.ImageScan.InitDelay = 60 * time.Second
		}
		if cfg.ImageScan.ServiceAccountName == "" {
			// Do not set default sa for image scan. This can break existing kvisors since we can't add new service accounts.
			cfg.ImageScan.ServiceAccountName = ""
		}
	}
	if cfg.CloudScan.Enabled {
		if cfg.CloudScan.ScanInterval == 0 {
			cfg.CloudScan.ScanInterval = 1 * time.Hour
		}
	}
	if cfg.KubeBench.Enabled {
		if cfg.KubeBench.ScanInterval == 0 {
			cfg.KubeBench.ScanInterval = 30 * time.Second
		}
		if cfg.KubeBench.Image.Name == "" {
			cfg.KubeBench.Image.Name = "ghcr.io/castai/kvisor/kube-bench:v0.8.0"
			cfg.KubeBench.Image.PullPolicy = "IfNotPresent"
		}
	}
	if cfg.Linter.Enabled {
		if cfg.Linter.ScanInterval == 0 {
			cfg.Linter.ScanInterval = 30 * time.Second
		}
	}

	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 6060
	}
	if cfg.Provider == "" {
		cfg.Provider = "on-premise"
	}
	if cfg.DeltaSyncInterval == 0 {
		cfg.DeltaSyncInterval = 15 * time.Second
	}
	if cfg.StatusPort == 0 {
		cfg.StatusPort = 7071
	}
	if cfg.Telemetry.Interval == 0 {
		cfg.Telemetry.Interval = 1 * time.Minute
	}

	return cfg, nil
}

func required(variable string) error {
	return fmt.Errorf("env variable %s is required", variable)
}
