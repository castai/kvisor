package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/castai/kvisor/cmd/agent/daemon/app"
	"github.com/castai/kvisor/cmd/agent/daemon/state"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func lookupConfigVariable(name string) (string, error) {
	key, found := os.LookupEnv("CASTAI_" + name)
	if found {
		return key, nil
	}

	key, found = os.LookupEnv(name)
	if found {
		return key, nil
	}

	return "", fmt.Errorf("environment variable missing: please provide either `CAST_%s` or `%s`", name, name)
}

func NewRunCommand(version string) *cobra.Command {
	var (
		logLevel        = pflag.String("log-level", slog.LevelInfo.String(), "log level")
		logRateInterval = pflag.Duration("log-rate-iterval", 100*time.Millisecond, "Log rate limit interval")
		logRateBurst    = pflag.Int("log-rate-burst", 100, "Log rate burst")

		sendLogLevel          = pflag.String("send-logs-level", "", "send logs level")
		containerdSockPath    = pflag.String("containerd-sock", "/run/containerd/containerd.sock", "Path to containerd socket file")
		metricsHTTPListenPort = pflag.Int("metrics-http-listen-port", 6060, "metrics http listen port")
		pyroscopeAddr         = pflag.String("pyroscope-addr", "", "Enable pyroscope tracing")
		hostCgroupsDir        = pflag.String("host-cgroups", "/cgroups", "Host /sys/fs/cgroups directory name mounted to container")

		containerStatsEnabled        = pflag.Bool("container-stats-enabled", false, "Enable container stats scraping")
		containerStatsScrapeInterval = pflag.Duration("container-stats-scrape-interval", 60*time.Second, "Container resources scrape interval")

		btfPath           = pflag.String("btf-path", "/sys/kernel/btf/vmlinux", "btf file path")
		ebpfEventsEnabled = pflag.Bool("ebpf-events-enabled", false, "Enable ebpf events")
		ebpfEventsPolicy  = ebpftracer.EventsPolicyConfig{
			EnabledEvents: []events.ID{
				events.SockSetState,
				events.SchedProcessExec,
				events.NetPacketDNSBase,
				events.MagicWrite,
				events.ProcessOomKilled,
				events.StdioViaSocket,
				events.TtyWrite,
			},
		}
		ebpfEventsStdioExporterEnabled = pflag.Bool("ebpf-events-stdio-exporter-enabled", false, "Export ebpf event to stdio")
		ebpfEventsPerCPUBuffer         = pflag.Int("ebpf-events-per-cpu-buffer", os.Getpagesize()*64, "Ebpf per cpu buffer size")
		ebpfEventsOutputChanSize       = pflag.Int("ebpf-events-output-queue-size", 4096, "Ebpf user spaces output channel size")
		ebpfMetricsEnabled             = pflag.Bool("ebpf-metrics-enabled", false, "Enables the export of metrics from eBPF")

		mutedNamespaces = pflag.StringSlice("ignored-namespaces", []string{"kube-system", "calico", "calico-system"},
			"List of namespaces to ignore tracing events for. To ignore multiple namespaces, separate by comma or pass flag multiple times."+
				" For example: --ignored-namespaces=kube-system,calico-system")

		fileHashEnrichedEnabled = pflag.Bool("file-hash-enricher-enabled", false, "Enables the file has event enricher for exec events")

		signatureEngineInputEventChanSize  = pflag.Int("signature-engine-input-queue-size", 1000, "Input queue size for the signature engine")
		signatureEngineOutputEventChanSize = pflag.Int("signature-engine-output-queue-size", 1000, "Output queue size for the signature engine")
		socks5DetectionSignatureEnabled    = pflag.Bool("signature-socks5-detection-enabled", false, "Enables the socks5 detection signature")
		socks5DetectionSignatureCacheSize  = pflag.Uint32("signature-socks5-detection-cache-size", 1024, "Configures the amount of state machine cache entries to detect socks5 information")

		netflowEnabled                     = pflag.Bool("netflow-enabled", false, "Enables netflow tracking")
		netflowSampleSubmitIntervalSeconds = pflag.Uint64("netflow-sample-submit-interval-seconds", 15, "Netflow sample submit interval")
		netflowOutputChanSize              = pflag.Int("netflow-output-queue-size", 4096, "Netflow output queue size")
		netflowExportInterval              = pflag.Duration("netflow-export-interval", 15*time.Second, "Netflow export interval")
		netflowGrouping                    = ebpftracer.NetflowGroupingDropSrcPort

		processTreeEnabled = pflag.Bool("process-tree-enabled", false, "Enables process tree tracking")

		clickhouseAddr     = pflag.String("clickhouse-addr", "", "Clickhouse address to send events to")
		clickhouseDatabase = pflag.String("clickhouse-database", "", "Clickhouse database name")
		clickhouseUsername = pflag.String("clickhouse-username", "", "Clickhouse username")

		castaiServerInsecure = pflag.Bool("castai-server-insecure", false, "Use insecure connection to castai grpc server. Used for e2e.")

		kubeAPIServiceAddr = pflag.String("kube-api-service-addr", "", "Custom kube API service grpc address")

		exportersQueueSize = pflag.Int("exporters-queue-size", 4096, "Exporters queue size")

		redactSensitiveValuesRegexStr = pflag.String("redact-sensitive-values-regex", "", "Regex which will be used to detect sensitive values in process exec args")
	)

	pflag.Var(&netflowGrouping, "netflow-grouping", "Group netflow to reduce cardinality. Eg: drop_src_port to drop source port")
	pflag.Var(&ebpfEventsPolicy, "ebpf-events-policy", "Specify which ebpf events should be traced")

	command := &cobra.Command{
		Use: "run",
		Run: func(cmd *cobra.Command, args []string) {
			pflag.Parse()

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			castaiClientCfg, err := resolveCastaiConfig(*castaiServerInsecure)
			if err != nil {
				slog.Warn(fmt.Errorf("skipping CAST AI integration: %w", err).Error())
			}

			var redactSensitiveValuesRegex *regexp.Regexp
			if *redactSensitiveValuesRegexStr != "" {
				var err error
				redactSensitiveValuesRegex, err = regexp.Compile(*redactSensitiveValuesRegexStr)
				if err != nil {
					slog.With("error", err).Error(`"redact-sensitive-values-regex" must be a valid regex expression`)
					os.Exit(1)
				}
			}

			if err := app.New(&app.Config{
				LogLevel:              *logLevel,
				LogRateInterval:       *logRateInterval,
				LogRateBurst:          *logRateBurst,
				SendLogsLevel:         *sendLogLevel,
				Version:               version,
				BTFPath:               *btfPath,
				PyroscopeAddr:         *pyroscopeAddr,
				ContainerdSockPath:    *containerdSockPath,
				HostCgroupsDir:        *hostCgroupsDir,
				MetricsHTTPListenPort: *metricsHTTPListenPort,
				ContainerStatsEnabled: *containerStatsEnabled,
				State: state.Config{
					ContainerStatsScrapeInterval: *containerStatsScrapeInterval,
					NetflowExportInterval:        *netflowExportInterval,
				},
				EBPFEventsEnabled:              *ebpfEventsEnabled,
				EBPFEventsStdioExporterEnabled: *ebpfEventsStdioExporterEnabled,
				EBPFEventsPerCPUBuffer:         *ebpfEventsPerCPUBuffer,
				EBPFEventsOutputChanSize:       *ebpfEventsOutputChanSize,
				EBPFMetricsEnabled:             *ebpfMetricsEnabled,
				EBPFEventsPolicyConfig:         ebpfEventsPolicy,
				MutedNamespaces:                *mutedNamespaces,
				SignatureEngineConfig: signature.SignatureEngineConfig{
					InputChanSize:  *signatureEngineInputEventChanSize,
					OutputChanSize: *signatureEngineOutputEventChanSize,
					DefaultSignatureConfig: signature.DefaultSignatureConfig{
						SOCKS5DetectedSignatureEnabled: *socks5DetectionSignatureEnabled,
						SOCKS5DetectedSignatureConfig: signature.SOCKS5DetectionSignatureConfig{
							CacheSize: *socks5DetectionSignatureCacheSize,
						},
					},
				},
				Castai: castaiClientCfg,
				EnricherConfig: app.EnricherConfig{
					EnableFileHashEnricher:     *fileHashEnrichedEnabled,
					RedactSensitiveValuesRegex: redactSensitiveValuesRegex,
				},
				Netflow: app.NetflowConfig{
					Enabled:                     *netflowEnabled,
					SampleSubmitIntervalSeconds: *netflowSampleSubmitIntervalSeconds,
					OutputChanSize:              *netflowOutputChanSize,
					Grouping:                    netflowGrouping,
				},
				Clickhouse: app.ClickhouseConfig{
					Addr:     *clickhouseAddr,
					Database: *clickhouseDatabase,
					Username: *clickhouseUsername,
					Password: os.Getenv("CLICKHOUSE_PASSWORD"),
				},
				ProcessTree: app.ProcessTreeConfig{
					Enabled: *processTreeEnabled,
				},
				KubeAPIServiceAddr: *kubeAPIServiceAddr,
				ExportersQueueSize: *exportersQueueSize,
			}).Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error(err.Error())
				os.Exit(1)
			}
		},
	}
	return command
}

func resolveCastaiConfig(castaiServerInsecure bool) (castai.Config, error) {
	castaiGRPCAddress, found := os.LookupEnv("CASTAI_API_GRPC_ADDR")
	if !found {
		return castai.Config{}, fmt.Errorf("missing environment variable: CASTAI_API_GRPC_ADDR")
	}
	castaiClusterID, found := os.LookupEnv("CASTAI_CLUSTER_ID")
	if !found {
		return castai.Config{}, fmt.Errorf("missing environment variable: CASTAI_CLUSTER_ID")
	}

	apiKey, err := lookupConfigVariable("API_KEY")
	if err != nil {
		return castai.Config{}, err
	}

	return castai.Config{
		APIKey:      apiKey,
		APIGrpcAddr: castaiGRPCAddress,
		ClusterID:   castaiClusterID,
		Insecure:    castaiServerInsecure,
	}, nil
}
