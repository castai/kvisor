package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	r := require.New(t)

	r.NoError(os.Setenv("KUBECONFIG", "~/.kube/config"))
	r.NoError(os.Setenv("API_URL", "https://api.cast.ai"))
	r.NoError(os.Setenv("API_KEY", "api-key"))
	r.NoError(os.Setenv("CLUSTER_ID", "c1"))
	r.NoError(os.Setenv("KUBECONFIG", "~/.kube/config"))
	r.NoError(os.Setenv("LEADER_ELECTION_ENABLED", "true"))
	r.NoError(os.Setenv("LEADER_ELECTION_NAMESPACE", "castai-sec-agent"))
	r.NoError(os.Setenv("LEADER_ELECTION_LOCK_NAME", "castai-sec-agent"))
	r.NoError(os.Setenv("FEATURES_IMAGE_SCAN_ENABLED", "true"))
	r.NoError(os.Setenv("FEATURES_IMAGE_SCAN_INTERVAL", "15s"))
	r.NoError(os.Setenv("FEATURES_IMAGE_SCAN_MAX_CONCURRENT_SCANS", "5"))
	r.NoError(os.Setenv("FEATURES_IMAGE_SCAN_IMAGE_COLLECTOR_IMAGE", "img"))
	r.NoError(os.Setenv("FEATURES_KUBEBENCH_ENABLED", "true"))
	r.NoError(os.Setenv("FEATURES_KUBELINTER_ENABLED", "true"))

	cfg := Get()

	r.Equal("~/.kube/config", cfg.Kubeconfig)
	r.Equal("https://api.cast.ai", cfg.API.URL)
	r.Equal("api-key", cfg.API.Key)
	r.Equal("c1", cfg.ClusterID)
	r.Equal(true, cfg.LeaderElection.Enabled)
	r.Equal("castai-sec-agent", cfg.LeaderElection.Namespace)
	r.Equal("castai-sec-agent", cfg.LeaderElection.LockName)
	r.Equal(25, cfg.KubeClient.QPS)
	r.Equal(150, cfg.KubeClient.Burst)
	r.Equal(ImageScan{
		Enabled:             true,
		ScanInterval:        15 * time.Second,
		MaxConcurrentScans:  5,
		ImageCollectorImage: "img",
		DockerOptionsPath:   "/etc/docker/config.json",
	}, cfg.Features.ImageScan)
	r.Equal(KubeBench{Enabled: true}, cfg.Features.KubeBench)
	r.Equal(KubeLinter{Enabled: true}, cfg.Features.KubeLinter)
}
