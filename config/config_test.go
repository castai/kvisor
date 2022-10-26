package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestConfig(t *testing.T) {
	t.Run("load config from file", func(t *testing.T) {
		r := require.New(t)
		expectedCfg := newTestConfig()

		cfgBytes, err := yaml.Marshal(expectedCfg)
		r.NoError(err)
		cfgFilePath := filepath.Join(t.TempDir(), "config.yaml")
		r.NoError(os.WriteFile(cfgFilePath, cfgBytes, 0600))

		actualCfg, err := Load(cfgFilePath)
		r.NoError(err)
		r.Equal(expectedCfg, actualCfg)
	})

	t.Run("override config from env variables", func(t *testing.T) {
		r := require.New(t)
		expectedCfg := newTestConfig()
		expectedCfg.API.Key = "api-key-from-env"
		r.NoError(os.Setenv("API_KEY", expectedCfg.API.Key))

		cfgBytes, err := yaml.Marshal(expectedCfg)
		r.NoError(err)
		cfgFilePath := filepath.Join(t.TempDir(), "config.yaml")
		r.NoError(os.WriteFile(cfgFilePath, cfgBytes, 0600))

		actualCfg, err := Load(cfgFilePath)
		r.NoError(err)
		r.Equal(expectedCfg, actualCfg)
	})
}

func newTestConfig() Config {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = "/kube/config"
	}
	return Config{
		PodIP: "10.10.1.123",
		KubeClient: KubeClient{
			QPS:            1,
			Burst:          5,
			KubeConfigPath: kubeconfig,
		},
		Log:               Log{Level: "info"},
		API:               API{URL: "https://api-test.cast.ai", Key: "key", ClusterID: "c1"},
		PprofPort:         6090,
		Provider:          "gke",
		DeltaSyncInterval: 15 * time.Second,
		ImageScan: ImageScan{
			Enabled:            true,
			ScanInterval:       20 * time.Second,
			ScanTimeout:        5 * time.Minute,
			MaxConcurrentScans: 3,
			Image: ImageScanImage{
				Name:       "collector-img",
				PullPolicy: "IfNotPresent",
			},
			Mode:              "mode",
			DockerOptionsPath: "/etc/config/docker-config.json",
			BlobsCachePort:    8080,
			CPURequest:        "100m",
			CPULimit:          "2",
			MemoryRequest:     "100Mi",
			MemoryLimit:       "2Gi",
		},
		Linter: Linter{
			Enabled: true,
		},
		KubeBench: KubeBench{
			Enabled:      true,
			ScanInterval: 15 * time.Second,
		},
		CloudScan: CloudScan{
			Enabled:      true,
			ScanInterval: 1 * time.Hour,
			GKE: &CloudScanGKE{
				ClusterName:     "",
				CredentialsFile: "",
			},
			EKS: &CloudScanEKS{
				ClusterName: "",
			},
		},
	}
}
