package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	require.NoError(t, os.Setenv("KUBECONFIG", "~/.kube/config"))
	require.NoError(t, os.Setenv("LEADER_ELECTION_ENABLED", "true"))
	require.NoError(t, os.Setenv("LEADER_ELECTION_NAMESPACE", "castai-sec-agent"))
	require.NoError(t, os.Setenv("LEADER_ELECTION_LOCK_NAME", "castai-sec-agent"))

	cfg := Get()

	require.Equal(t, "~/.kube/config", cfg.Kubeconfig)
	require.Equal(t, true, cfg.LeaderElection.Enabled)
	require.Equal(t, "castai-sec-agent", cfg.LeaderElection.Namespace)
	require.Equal(t, "castai-sec-agent", cfg.LeaderElection.LockName)
	require.Equal(t, 25, cfg.KubeClient.QPS)
	require.Equal(t, 150, cfg.KubeClient.Burst)
}
