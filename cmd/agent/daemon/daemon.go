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
	command := &cobra.Command{
		Use: "run",
	}

	var (
		logLevel        = command.Flags().String("log-level", slog.LevelInfo.String(), "log level")
		logRateInterval = command.Flags().Duration("log-rate-interval", 100*time.Millisecond, "Log rate limit interval")
		logRateBurst    = command.Flags().Int("log-rate-burst", 100, "Log rate burst")

		promMetricsExportEnabled  = command.Flags().Bool("prom-metrics-export-enabled", false, "Enabled sending internal prometheus metrics")
		promMetricsExportInterval = command.Flags().Duration("prom-metrics-export-interval", 5*time.Minute, "Internal prometheus metrics export interval")

		sendLogLevel          = command.Flags().String("send-logs-level", "", "send logs level")
		containerdSockPath    = command.Flags().String("containerd-sock", "/run/containerd/containerd.sock", "Path to containerd socket file")
		metricsHTTPListenPort = command.Flags().Int("metrics-http-listen-port", 6060, "metrics http listen port")
		pyroscopeAddr         = command.Flags().String("pyroscope-addr", "", "Enable pyroscope tracing")
		hostCgroupsDir        = command.Flags().String("host-cgroups", "/cgroups", "Host /sys/fs/cgroups directory name mounted to container")

		statsEnabled        = command.Flags().Bool("stats-enabled", false, "Enable stats scraping")
		statsScrapeInterval = command.Flags().Duration("stats-scrape-interval", 60*time.Second, "Stats scrape interval")

		btfPath           = command.Flags().String("btf-path", "/sys/kernel/btf/vmlinux", "btf file path")
		ebpfEventsEnabled = command.Flags().Bool("ebpf-events-enabled", false, "Enable ebpf events")
		ebpfEventsPolicy  = ebpftracer.EventsPolicyConfig{
			EnabledEvents: []events.ID{
				events.SockSetState,
				events.SchedProcessExec,
				events.NetPacketDNSBase,
				events.MagicWrite,
				events.ProcessOomKilled,
				// events.StdioViaSocket, // TODO(anjmao): Tracing this event via syscall hooks is very expensive. Rework the whole syscall tracing.
				events.TtyWrite,
				events.NetPacketSSHBase,
			},
		}
		ebpfEventsStdioExporterEnabled = command.Flags().Bool("ebpf-events-stdio-exporter-enabled", false, "Export ebpf event to stdio")
		ebpfEventsOutputChanSize       = command.Flags().Int("ebpf-events-output-queue-size", 4096, "Ebpf user spaces output channel size")
		ebpfTracerMetricsEnabled       = command.Flags().Bool("ebpf-tracer-metrics-enabled", true, "Enables the export of tracer related metrics from eBPF")
		ebpfProgramMetricsEnabled      = command.Flags().Bool("ebpf-program-metrics-enabled", false, "Enables the export of metrics about eBPF programs")

		EBPFSignalEventsRingBufferSize = command.Flags().Uint32("ebpf-signal-events-ring-buffer-size", 1<<20, "Ebpf ring buffer size in bytes for priority events. Should be power of 2")
		EBPFEventsRingBufferSize       = command.Flags().Uint32("ebpf-events-ring-buffer-size", 1<<20, "Ebpf ring buffer size in bytes for events. Should be power of 2")
		EBPFSkbEventsRingBufferSize    = command.Flags().Uint32("ebpf-skb-events-ring-buffer-size", 1<<20, "Ebpf ring buffer size in bytes for skb network events. Should be power of 2")

		mutedNamespaces = command.Flags().StringSlice("ignored-namespaces", []string{"kube-system", "calico", "calico-system"},
			"List of namespaces to ignore tracing events for. To ignore multiple namespaces, separate by comma or pass flag multiple times."+
				" For example: --ignored-namespaces=kube-system,calico-system")

		fileHashEnrichedEnabled = command.Flags().Bool("file-hash-enricher-enabled", false, "Enables the file has event enricher for exec events")

		signatureEngineInputEventChanSize  = command.Flags().Int("signature-engine-input-queue-size", 1000, "Input queue size for the signature engine")
		signatureEngineOutputEventChanSize = command.Flags().Int("signature-engine-output-queue-size", 1000, "Output queue size for the signature engine")
		socks5DetectionSignatureEnabled    = command.Flags().Bool("signature-socks5-detection-enabled", false, "Enables the socks5 detection signature")
		socks5DetectionSignatureCacheSize  = command.Flags().Uint32("signature-socks5-detection-cache-size", 1024, "Configures the amount of state machine cache entries to detect socks5 information")

		netflowEnabled                     = command.Flags().Bool("netflow-enabled", false, "Enables netflow tracking")
		netflowSampleSubmitIntervalSeconds = command.Flags().Uint64("netflow-sample-submit-interval-seconds", 15, "Netflow sample submit interval")
		netflowExportInterval              = command.Flags().Duration("netflow-export-interval", 15*time.Second, "Netflow export interval")
		netflowGrouping                    = ebpftracer.NetflowGroupingDropSrcPort

		processTreeEnabled = command.Flags().Bool("process-tree-enabled", false, "Enables process tree tracking")

		clickhouseAddr     = command.Flags().String("clickhouse-addr", "", "Clickhouse address to send events to")
		clickhouseDatabase = command.Flags().String("clickhouse-database", "", "Clickhouse database name")
		clickhouseUsername = command.Flags().String("clickhouse-username", "", "Clickhouse username")

		castaiServerInsecure = command.Flags().Bool("castai-server-insecure", false, "Use insecure connection to castai grpc server. Used for e2e.")

		kubeAPIServiceAddr = command.Flags().String("kube-api-service-addr", "", "Custom kube API service grpc address")

		exportersQueueSize = command.Flags().Int("exporters-queue-size", 4096, "Exporters queue size")

		automountCgroupv2 = command.Flags().Bool("automount-cgroupv2", true, "Automount cgroupv2 if not mounted")

		redactSensitiveValuesRegexStr = command.Flags().String("redact-sensitive-values-regex", "", "Regex which will be used to detect sensitive values in process exec args")

		criEndpoint          = command.Flags().String("cri-endpoint", "unix:///run/containerd/containerd.sock", "CRI endpoint")
		ebpfEventLabels      = command.Flags().StringSlice("ebpf-events-include-pod-labels", []string{}, "List of label keys to be sent with eBPF events, separated by comma")
		ebpfEventAnnotations = command.Flags().StringSlice("ebpf-events-include-pod-annotations", []string{}, "List of annotation keys to be sent with eBPF events, separated by comma")
	)

	command.Flags().Var(&netflowGrouping, "netflow-grouping", "Group netflow to reduce cardinality. Eg: drop_src_port to drop source port")
	command.Flags().Var(&ebpfEventsPolicy, "ebpf-events-policy", "Specify which ebpf events should be traced")

	command.Run = func(cmd *cobra.Command, args []string) {
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
			LogLevel:                  *logLevel,
			LogRateInterval:           *logRateInterval,
			LogRateBurst:              *logRateBurst,
			SendLogsLevel:             *sendLogLevel,
			PromMetricsExportEnabled:  *promMetricsExportEnabled,
			PromMetricsExportInterval: *promMetricsExportInterval,
			Version:                   version,
			BTFPath:                   *btfPath,
			PyroscopeAddr:             *pyroscopeAddr,
			ContainerdSockPath:        *containerdSockPath,
			HostCgroupsDir:            *hostCgroupsDir,
			MetricsHTTPListenPort:     *metricsHTTPListenPort,
			StatsEnabled:              *statsEnabled,
			State: state.Config{
				StatsScrapeInterval:   *statsScrapeInterval,
				NetflowExportInterval: *netflowExportInterval,
			},
			EBPFEventsEnabled:              *ebpfEventsEnabled,
			EBPFEventsStdioExporterEnabled: *ebpfEventsStdioExporterEnabled,
			EBPFEventsOutputChanSize:       *ebpfEventsOutputChanSize,
			EBPFMetrics: app.EBPFMetricsConfig{
				TracerMetricsEnabled:  *ebpfTracerMetricsEnabled,
				ProgramMetricsEnabled: *ebpfProgramMetricsEnabled,
			},
			EBPFEventsPolicyConfig:         ebpfEventsPolicy,
			EBPFSignalEventsRingBufferSize: *EBPFSignalEventsRingBufferSize,
			EBPFEventsRingBufferSize:       *EBPFEventsRingBufferSize,
			EBPFSkbEventsRingBufferSize:    *EBPFSkbEventsRingBufferSize,
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
			AutomountCgroupv2:  *automountCgroupv2,
			CRIEndpoint:        *criEndpoint,
			EventLabels:        *ebpfEventLabels,
			EventAnnotations:   *ebpfEventAnnotations,
		}).Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error(err.Error())
			os.Exit(1)
		}
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
