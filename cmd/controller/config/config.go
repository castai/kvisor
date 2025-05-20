package config

import (
	"time"

	"github.com/castai/kvisor/cmd/controller/state"
	"github.com/castai/kvisor/cmd/controller/state/imagescan"
	"github.com/castai/kvisor/cmd/controller/state/kubebench"
	"github.com/castai/kvisor/cmd/controller/state/kubelinter"
	"github.com/castai/kvisor/pkg/castai"
)

type Config struct {
	// Logging configuration.
	LogLevel        string        `json:"logLevel"`
	LogRateInterval time.Duration `json:"logRateInterval"`
	LogRateBurst    int           `json:"logRateBurst"`

	PromMetricsExportEnabled  bool          `json:"promMetricsExportEnabled"`
	PromMetricsExportInterval time.Duration `json:"promMetricsExportInterval"`

	// Built binary version.
	Version      string `json:"version"`
	ChartVersion string `json:"chartVersion"`

	// Current running pod metadata.
	PodNamespace string `validate:"required" json:"podNamespace"`
	PodName      string `validate:"required" json:"podName"`

	// HTTPListenPort is internal http servers listen port.
	HTTPListenPort        int `validate:"required" json:"HTTPListenPort"`
	MetricsHTTPListenPort int `json:"metricsHTTPListenPort"`
	KubeServerListenPort  int `validate:"required" json:"kubeServerListenPort"`

	CastaiController state.CastaiConfig      `json:"castaiController"`
	CastaiEnv        castai.Config           `json:"castaiEnv"`
	ImageScan        imagescan.Config        `json:"imageScan"`
	Linter           kubelinter.Config       `json:"linter"`
	KubeBench        kubebench.Config        `json:"kubeBench"`
	JobsCleanup      state.JobsCleanupConfig `json:"jobsCleanup"`
	AgentConfig      AgentConfig             `json:"agentConfig"`
}

type AgentConfig struct {
	Enabled bool `json:"enabled"`
}
