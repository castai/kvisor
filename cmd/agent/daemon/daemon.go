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

	"github.com/spf13/cobra"
	"google.golang.org/grpc/encoding/gzip"

	"github.com/castai/kvisor/cmd/agent/daemon/app"
	"github.com/castai/kvisor/cmd/agent/daemon/config"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
)

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

		sendLogLevel          = command.Flags().String("send-logs-level", slog.LevelInfo.String(), "send logs level")
		containerdSockPath    = command.Flags().String("containerd-sock", "/run/containerd/containerd.sock", "Path to containerd socket file")
		metricsHTTPListenPort = command.Flags().Int("metrics-http-listen-port", 6060, "metrics http listen port")
		hostCgroupsDir        = command.Flags().String("host-cgroups", "/cgroups", "Host /sys/fs/cgroups directory name mounted to container")

		statsEnabled           = command.Flags().Bool("stats-enabled", false, "Enable stats scraping")
		statsScrapeInterval    = command.Flags().Duration("stats-scrape-interval", 60*time.Second, "Stats scrape interval")
		statsFileAccessEnabled = command.Flags().Bool("stats-file-access-enabled", false, "Enable file access stats tracking")
		storageStatsEnabled    = command.Flags().Bool("storage-stats-enabled", false, "Enable storage stats scraping")

		btfPath           = command.Flags().String("btf-path", "/sys/kernel/btf/vmlinux", "btf file path")
		ebpfEventsEnabled = command.Flags().Bool("ebpf-events-enabled", false, "Enable ebpf events")
		// Default events are sock_set_state,sched_process_exec,sched_process_exit,net_packet_dns_base,magic_write,process_oom_killed,net_packet_ssh_base
		ebpfEventsPolicy = ebpftracer.EventsPolicyConfig{
			EnabledEvents: []events.ID{
				events.SockSetState,
				events.SchedProcessExec,
				events.SchedProcessExit,
				events.NetPacketDNSBase,
				events.MagicWrite,
				events.ProcessOomKilled,
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

		signatureEngineInputEventChanSize                = command.Flags().Int("signature-engine-input-queue-size", 1000, "Input queue size for the signature engine")
		signatureEngineOutputEventChanSize               = command.Flags().Int("signature-engine-output-queue-size", 1000, "Output queue size for the signature engine")
		socks5DetectionSignatureEnabled                  = command.Flags().Bool("signature-socks5-detection-enabled", false, "Enables the socks5 detection signature")
		socks5DetectionSignatureCacheSize                = command.Flags().Uint32("signature-socks5-detection-cache-size", 1024, "Configures the amount of state machine cache entries to detect socks5 information")
		gitCloneDetectionSignatureEnabled                = command.Flags().Bool("signature-git-clone-detection-enabled", false, "Enables the git clone detection signature")
		gitCloneDetectionSignatureRedactPasswords        = command.Flags().Bool("signature-git-clone-detection-redact-password", true, "If enabled, any password passed via the URL gets redacted")
		ingressNightmareExploitDetectionSignatureEnabled = command.Flags().Bool("signature-ingress-nightmare-exploit-detection-enabled", true, "Enables the detection signature to detect exploits of ingress nightmare")

		netflowEnabled                    = command.Flags().Bool("netflow-enabled", false, "Enables netflow tracking")
		netflowCheckClusterNetworkRanges  = command.Flags().Bool("netflow-check-cluster-network-ranges", true, "Check cluster network ranges before enriching destinations")
		netflowClusterInfoRefreshInterval = command.Flags().Duration("netflow-cluster-network-ranges-refresh-interval", 1*time.Hour, "Cluster network ranges refresh interval (0 to disable periodic refresh)")
		netflowExportInterval             = command.Flags().Duration("netflow-export-interval", 15*time.Second, "Netflow export interval")
		netflowMaxPublicIPsBucket         = command.Flags().Int16("netflow-max-public-ips-bucket", -1, "Maximum number of unique public IPs destination before aggregating into 0.0.0.0 range")
		netflowCgroupDnsCacheMaxEntries   = command.Flags().Uint32("netflow-cgroup-dns-cache-max-entries", 1024, "Number of dns cache entries per cgroup")
		netflowGrouping                   = ebpftracer.NetflowGroupingDropSrcPort

		processTreeEnabled = command.Flags().Bool("process-tree-enabled", false, "Enables process tree tracking")

		dataBatchMaxSize       = command.Flags().Uint32("data-batch-max-size", 524288, "Data batch max size in bytes (before compression)")
		dataBatchFlushInterval = command.Flags().Duration("data-batch-flush-interval", 15*time.Second, "Data batch flush interval. Data is flushed periodically if data batch size is not reached")
		dataBatchExportTimeout = command.Flags().Duration("data-batch-export-timeout", 10*time.Second, "Data batch export timeout")

		clickhouseAddr     = command.Flags().String("clickhouse-addr", "", "Clickhouse address to send events to")
		clickhouseDatabase = command.Flags().String("clickhouse-database", "", "Clickhouse database name")
		clickhouseUsername = command.Flags().String("clickhouse-username", "", "Clickhouse username")

		castaiServerInsecure  = command.Flags().Bool("castai-server-insecure", false, "Use insecure connection to castai grpc server. Used for e2e.")
		castaiCompressionName = command.Flags().String("castai-compression-name", gzip.Name, "CASTAI gRPC compression name")

		kubeAPIServiceAddr = command.Flags().String("kube-api-service-addr", "", "Custom kube API service grpc address")

		exportersQueueSize = command.Flags().Int("exporters-queue-size", 4096, "Exporters queue size")

		automountCgroupv2 = command.Flags().Bool("automount-cgroupv2", true, "Automount cgroupv2 if not mounted")

		redactSensitiveValuesRegexStr = command.Flags().String("redact-sensitive-values-regex", "", "Regex which will be used to detect sensitive values in process exec args")

		criEndpoint          = command.Flags().String("cri-endpoint", "unix:///run/containerd/containerd.sock", "CRI endpoint")
		ebpfEventLabels      = command.Flags().StringSlice("ebpf-events-include-pod-labels", []string{}, "List of label keys to be sent with eBPF events, separated by comma")
		ebpfEventAnnotations = command.Flags().StringSlice("ebpf-events-include-pod-annotations", []string{}, "List of annotation keys to be sent with eBPF events, separated by comma")

		containersRefreshInterval = command.Flags().Duration("containers-refresh-interval", 2*time.Minute, "Containers refresh interval")
	)

	command.Flags().Var(&netflowGrouping, "netflow-grouping", "Group netflow to reduce cardinality. Eg: drop_src_port to drop source port")
	command.Flags().Var(&ebpfEventsPolicy, "ebpf-events-policy", "Specify which ebpf events should be traced")

	command.Run = func(cmd *cobra.Command, args []string) {
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		castaiClientCfg, err := castai.NewConfigFromEnv(*castaiServerInsecure)
		if err != nil {
			slog.Warn(fmt.Errorf("failed to initialize CAST AI client config: %w", err).Error())
		}
		castaiClientCfg.CompressionName = *castaiCompressionName

		var redactSensitiveValuesRegex *regexp.Regexp
		if *redactSensitiveValuesRegexStr != "" {
			var err error
			redactSensitiveValuesRegex, err = regexp.Compile(*redactSensitiveValuesRegexStr)
			if err != nil {
				slog.With("error", err).Error(`"redact-sensitive-values-regex" must be a valid regex expression`)
				os.Exit(1)
			}
		}

		if err := app.New(&config.Config{
			LogLevel:                  *logLevel,
			LogRateInterval:           *logRateInterval,
			LogRateBurst:              *logRateBurst,
			SendLogsLevel:             *sendLogLevel,
			PromMetricsExportEnabled:  *promMetricsExportEnabled,
			PromMetricsExportInterval: *promMetricsExportInterval,
			Version:                   version,
			BTFPath:                   *btfPath,
			ContainerdSockPath:        *containerdSockPath,
			HostCgroupsDir:            *hostCgroupsDir,
			MetricsHTTPListenPort:     *metricsHTTPListenPort,
			DataBatch: config.DataBatchConfig{
				MaxBatchSizeBytes: int(*dataBatchMaxSize),
				FlushInterval:     *dataBatchFlushInterval,
				ExportTimeout:     *dataBatchExportTimeout,
			},
			Stats: config.StatsConfig{
				Enabled:           *statsEnabled,
				ScrapeInterval:    *statsScrapeInterval,
				FileAccessEnabled: *statsFileAccessEnabled,
				StorageEnabled:    *storageStatsEnabled,
			},
			Events: config.EventsConfig{
				Enabled: *ebpfEventsEnabled,
			},
			EBPFEventsStdioExporterEnabled: *ebpfEventsStdioExporterEnabled,
			EBPFEventsOutputChanSize:       *ebpfEventsOutputChanSize,
			EBPFMetrics: config.EBPFMetricsConfig{
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
					GitCloneDetectedSignatureEnabled: *gitCloneDetectionSignatureEnabled,
					GitCloneDetectedSignatureConfig: signature.GitCloneSignatureConfig{
						RedactPasswords: *gitCloneDetectionSignatureRedactPasswords,
					},
					IngressNightmareExploitSignatureEnabled: *ingressNightmareExploitDetectionSignatureEnabled,
					IngressNightmareExploitSignatureConfig:  signature.IngressNightmareDetectedConfig{},
				},
			},
			Castai: castaiClientCfg,
			EnricherConfig: config.EnricherConfig{
				EnableFileHashEnricher:     *fileHashEnrichedEnabled,
				RedactSensitiveValuesRegex: redactSensitiveValuesRegex,
			},
			Netflow: config.NetflowConfig{
				Enabled:                    *netflowEnabled,
				Grouping:                   netflowGrouping,
				ExportInterval:             *netflowExportInterval,
				MaxPublicIPs:               *netflowMaxPublicIPsBucket,
				CheckClusterNetworkRanges:  *netflowCheckClusterNetworkRanges,
				ClusterInfoRefreshInterval: *netflowClusterInfoRefreshInterval,
				CgroupDNSCacheMaxEntries:   *netflowCgroupDnsCacheMaxEntries,
			},
			Clickhouse: config.ClickhouseConfig{
				Addr:     *clickhouseAddr,
				Database: *clickhouseDatabase,
				Username: *clickhouseUsername,
				Password: os.Getenv("CLICKHOUSE_PASSWORD"),
			},
			ProcessTree: config.ProcessTreeConfig{
				Enabled: *processTreeEnabled,
			},
			KubeAPIServiceAddr:        *kubeAPIServiceAddr,
			ExportersQueueSize:        *exportersQueueSize,
			AutomountCgroupv2:         *automountCgroupv2,
			CRIEndpoint:               *criEndpoint,
			EventLabels:               *ebpfEventLabels,
			EventAnnotations:          *ebpfEventAnnotations,
			ContainersRefreshInterval: *containersRefreshInterval,
		}).Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}

	return command
}
