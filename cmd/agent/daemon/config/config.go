package config

import (
	"regexp"
	"time"

	"github.com/castai/kvisor/cmd/agent/daemon/state"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
)

type EBPFMetricsConfig struct {
	TracerMetricsEnabled  bool `json:"TracerMetricsEnabled"`
	ProgramMetricsEnabled bool `json:"ProgramMetricsEnabled"`
}

type Config struct {
	LogLevel                       string                          `json:"logLevel"`
	LogRateInterval                time.Duration                   `json:"logRateInterval"`
	LogRateBurst                   int                             `json:"logRateBurst"`
	SendLogsLevel                  string                          `json:"sendLogsLevel"`
	PromMetricsExportEnabled       bool                            `json:"promMetricsExportEnabled"`
	PromMetricsExportInterval      time.Duration                   `json:"promMetricsExportInterval"`
	Version                        string                          `json:"version"`
	BTFPath                        string                          `json:"BTFPath"`
	ContainerdSockPath             string                          `json:"containerdSockPath"`
	HostCgroupsDir                 string                          `json:"hostCgroupsDir"`
	MetricsHTTPListenPort          int                             `json:"metricsHTTPListenPort"`
	State                          state.Config                    `json:"state"`
	StatsEnabled                   bool                            `json:"statsEnabled"`
	EBPFEventsEnabled              bool                            `json:"EBPFEventsEnabled"`
	EBPFEventsOutputChanSize       int                             `validate:"required" json:"EBPFEventsOutputChanSize"`
	EBPFEventsStdioExporterEnabled bool                            `json:"EBPFEventsStdioExporterEnabled"`
	EBPFMetrics                    EBPFMetricsConfig               `json:"EBPFMetrics"`
	EBPFEventsPolicyConfig         ebpftracer.EventsPolicyConfig   `json:"EBPFEventsPolicyConfig"`
	EBPFSignalEventsRingBufferSize uint32                          `json:"EBPFSignalEventsRingBufferSize"`
	EBPFEventsRingBufferSize       uint32                          `json:"EBPFEventsRingBufferSize"`
	EBPFSkbEventsRingBufferSize    uint32                          `json:"EBPFSkbEventsRingBufferSize"`
	MutedNamespaces                []string                        `json:"mutedNamespaces"`
	SignatureEngineConfig          signature.SignatureEngineConfig `json:"signatureEngineConfig"`
	Castai                         castai.Config                   `json:"castai"`
	EnricherConfig                 EnricherConfig                  `json:"enricherConfig"`
	Netflow                        NetflowConfig                   `json:"netflow"`
	ProcessTree                    ProcessTreeConfig               `json:"processTree"`
	Clickhouse                     ClickhouseConfig                `json:"clickhouse"`
	KubeAPIServiceAddr             string                          `json:"kubeAPIServiceAddr"`
	ExportersQueueSize             int                             `validate:"required" json:"exportersQueueSize"`
	AutomountCgroupv2              bool                            `json:"automountCgroupv2"`
	CRIEndpoint                    string                          `json:"criEndpoint"`
	EventLabels                    []string                        `json:"eventLabels"`
	EventAnnotations               []string                        `json:"eventAnnotations"`
	ContainersRefreshInterval      time.Duration                   `json:"containersRefreshInterval"`
}

type EnricherConfig struct {
	EnableFileHashEnricher     bool           `json:"enableFileHashEnricher"`
	RedactSensitiveValuesRegex *regexp.Regexp `json:"redactSensitiveValuesRegex"`
}

type NetflowConfig struct {
	Enabled                     bool                       `json:"enabled"`
	SampleSubmitIntervalSeconds uint64                     `json:"sampleSubmitIntervalSeconds"`
	Grouping                    ebpftracer.NetflowGrouping `json:"grouping"`
}

type ClickhouseConfig struct {
	Addr     string `json:"addr"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ProcessTreeConfig struct {
	Enabled bool `json:"enabled"`
}
