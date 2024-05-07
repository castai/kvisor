package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/castai/kvisor/cmd/agent/daemon/app"
	"github.com/castai/kvisor/cmd/agent/daemon/state"
	"github.com/castai/kvisor/pkg/castai"
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

		sendLogLevel       = pflag.String("send-logs-level", "", "send logs level")
		containerdSockPath = pflag.String("containerd-sock", "/run/containerd/containerd.sock", "Path to containerd socket file")
		//eventsQueueSize              = pflag.Int("events-queue-size", 65536, "Events batch size")
		metricsHTTPListenPort        = pflag.Int("metrics-http-listen-port", 6060, "metrics http listen port")
		pyroscopeAddr                = pflag.String("pyroscope-addr", "", "Enable pyroscope tracing")
		hostCgroupsDir               = pflag.String("host-cgroups", "/cgroups", "Host /sys/fs/cgroups directory name mounted to container")
		containerStatsScrapeInterval = pflag.Duration("container-stats-scrape-interval", 60*time.Second, "Container resources scrape interval")

		btfPath                        = pflag.String("btf-path", "/sys/kernel/btf/vmlinux", "btf file path")
		ebpfEventsStdioExporterEnabled = pflag.Bool("ebpf-events-stdio-exporter-enabled", false, "Export ebpf event to stdio")
		ebpfEventsPerCPUBuffer         = pflag.Int("ebpf-events-per-cpu-buffer", os.Getpagesize()*64, "Ebpf per cpu buffer size")
		ebpfEventsOutputChanSize       = pflag.Int("ebpf-events-output-queue-size", 10000, "Ebpf user spaces output channel size")

		signatureEngineInputEventChanSize  = pflag.Int("signature-engine-input-queue-size", 1000, "Input queue size for the signature engine.")
		signatureEngineOutputEventChanSize = pflag.Int("signature-engine-output-queue-size", 1000, "Output queue size for the signature engine.")

		mutedNamespaces = pflag.StringArray("mute-namespace", []string{"kube-system", "calico", "calico-system"}, "List of namespaces to ignore tracing events for. To mute multiple namespaces, provide this flag multiple times.")

		fileHashEnrichedEnabled           = pflag.Bool("file-hash-enricher-enabled", false, "Enables the file has event enricher for exec events")
		ttyDetectionSignatureEnabled      = pflag.Bool("signature-tty-detection-enabled", false, "Enables the tty detection signature")
		socks5DetectionSignatureEnabled   = pflag.Bool("signature-socks5-detection-enabled", false, "Enables the socks5 detection signature")
		socks5DetectionSignatureCacheSize = pflag.Uint32("signature-socks5-detection-cache-size", 1024, "Configures the amount of state machine cache entries to detect socks5 information")

		netflowEnabled                     = pflag.Bool("netflow-enabled", false, "Enables netflow tracking")
		netflowSampleSubmitIntervalSeconds = pflag.Uint64("netflow-sample-submit-interval-seconds", 15, "Netflow sample submit interval")
		netflowExportInterval              = pflag.Duration("netflow-export-interval", 15*time.Second, "Netflow export interval")
		netflowCleanupInterval             = pflag.Duration("netflow-cleanup-interval", 15*time.Second, "Netflow cleanup interval")

		clickhouseAddr     = pflag.String("clickhouse-addr", "", "Clickhouse address to send events to")
		clickhouseDatabase = pflag.String("clickhouse-database", "", "Clickhouse database name")
		clickhouseUsername = pflag.String("clickhouse-username", "", "Clickhouse username")

		castaiServerInsecure = pflag.Bool("castai-server-insecure", false, "Use insecure connection to castai grpc server. Used for e2e.")

		kubeAPIServiceAddr = pflag.String("kube-api-service-addr", "", "Custom kube API service grpc address")
	)

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
				State: state.Config{
					ContainerStatsScrapeInterval: *containerStatsScrapeInterval,
					NetflowExportInterval:        *netflowExportInterval,
					NetflowCleanupInterval:       *netflowCleanupInterval,
				},
				EBPFEventsStdioExporterEnabled: *ebpfEventsStdioExporterEnabled,
				EBPFEventsPerCPUBuffer:         *ebpfEventsPerCPUBuffer,
				EBPFEventsOutputChanSize:       *ebpfEventsOutputChanSize,
				MutedNamespaces:                *mutedNamespaces,
				SignatureEngineConfig: signature.SignatureEngineConfig{
					InputChanSize:  *signatureEngineInputEventChanSize,
					OutputChanSize: *signatureEngineOutputEventChanSize,
					DefaultSignatureConfig: signature.DefaultSignatureConfig{
						TTYDetectedSignatureEnabled:    *ttyDetectionSignatureEnabled,
						SOCKS5DetectedSignatureEnabled: *socks5DetectionSignatureEnabled,
						SOCKS5DetectedSignatureConfig: signature.SOCKS5DetectionSignatureConfig{
							CacheSize: *socks5DetectionSignatureCacheSize,
						},
					},
				},
				Castai: castaiClientCfg,
				EnricherConfig: app.EnricherConfig{
					EnableFileHashEnricher: *fileHashEnrichedEnabled,
				},
				Netflow: app.NetflowConfig{
					Enabled:                     *netflowEnabled,
					SampleSubmitIntervalSeconds: *netflowSampleSubmitIntervalSeconds,
				},
				Clickhouse: app.ClickhouseConfig{
					Addr:     *clickhouseAddr,
					Database: *clickhouseDatabase,
					Username: *clickhouseUsername,
					Password: os.Getenv("CLICKHOUSE_PASSWORD"),
				},
				KubeAPIServiceAddr: *kubeAPIServiceAddr,
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
