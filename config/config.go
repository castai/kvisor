package config

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Config struct {
	KubeClient     KubeClient
	Kubeconfig     string
	LeaderElection LeaderElection
	Log            Log
	API            API
	PprofPort      int
	ClusterID      string
	Provider       string
}

type KubeClient struct {
	// K8S client rate limiter allows bursts of up to 'burst' to exceed the QPS, while still maintaining a
	// smoothed qps rate of 'qps'.
	// The bucket is initially filled with 'burst' tokens, and refills at a rate of 'qps'.
	// The maximum number of tokens in the bucket is capped at 'burst'.
	QPS   int
	Burst int
}

type LeaderElection struct {
	Enabled   bool
	Namespace string
	LockName  string
}

type Log struct {
	Level int
}

type API struct {
	Key string
	URL string
}

var cfg *Config

func Get() Config {
	if cfg != nil {
		return *cfg
	}

	_ = viper.BindEnv("api.key", "API_KEY")
	_ = viper.BindEnv("api.url", "API_URL")
	_ = viper.BindEnv("clusterid", "CLUSTER_ID")
	_ = viper.BindEnv("kubeclient.qps", "KUBECLIENT_QPS")
	_ = viper.BindEnv("kubeclient.burst", "KUBECLIENT_BURST")
	_ = viper.BindEnv("kubeconfig")
	_ = viper.BindEnv("log.level", "LOG_LEVEL")
	_ = viper.BindEnv("leaderelection.enabled", "LEADER_ELECTION_ENABLED")
	_ = viper.BindEnv("leaderelection.namespace", "LEADER_ELECTION_NAMESPACE")
	_ = viper.BindEnv("leaderelection.lockname", "LEADER_ELECTION_LOCK_NAME")
	_ = viper.BindEnv("pprofport", "PPROF_PORT")
	_ = viper.BindEnv("provider", "PROVIDER")

	cfg = &Config{}
	if err := viper.Unmarshal(&cfg); err != nil {
		panic(fmt.Errorf("parsing configuration: %v", err))
	}

	if cfg.KubeClient.QPS == 0 {
		cfg.KubeClient.QPS = 25
	}
	if cfg.KubeClient.Burst == 0 {
		cfg.KubeClient.Burst = 150
	}
	if cfg.Log.Level == 0 {
		cfg.Log.Level = int(logrus.InfoLevel)
	}
	if cfg.LeaderElection.Enabled {
		if cfg.LeaderElection.Namespace == "" {
			required("LEADER_ELECTION_NAMESPACE")
		}
		if cfg.LeaderElection.LockName == "" {
			required("LEADER_ELECTION_LOCK_NAME")
		}
	}
	if cfg.PprofPort == 0 {
		cfg.PprofPort = 6060
	}
	if cfg.Provider == "" {
		cfg.Provider = "on-premise"
	}

	return *cfg
}

func required(variable string) {
	panic(fmt.Errorf("env variable %s is required", variable))
}
