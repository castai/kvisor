package daemon

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/castai/kvisor/cmd/agent/daemon/analyzers"
	"github.com/castai/kvisor/cmd/agent/daemon/app"
	"github.com/castai/kvisor/cmd/agent/daemon/state"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"
)

var (
	logLevel        = pflag.String("log-level", slog.LevelInfo.String(), "log level")
	logRateInterval = pflag.Duration("log-rate-iterval", 100*time.Millisecond, "Log rate limit interval")
	logRateBurst    = pflag.Int("log-rate-burst", 100, "Log rate burst")

	sendLogLevel                 = pflag.String("send-logs-level", "", "send logs level")
	containerdK8sPath            = pflag.String("containerd-k8s-path", "/run/containerd/io.containerd.runtime.v2.task/k8s.io", "Path to containerd k8s containers")
	containerdSockPath           = pflag.String("containerd-sock", "/run/containerd/containerd.sock", "Path to containerd socket file")
	ingestorAddr                 = pflag.String("ingestor-server-addr", "kvisord-server.kvisord.svc.cluster.local.:6061", "Ingestor server grpc API address")
	eventsQueueSize              = pflag.Int("events-queue-size", 65536, "Events batch size")
	httpListenPort               = pflag.Int("http-listen-port", 6061, "server listen port")
	pyroscopeAddr                = pflag.String("pyroscope-addr", "", "Enable pyroscope tracing")
	hostProcDir                  = pflag.String("host-proc-dir", "/hostproc", "Host /proc directory name mounted to container")
	hostCgroupsDir               = pflag.String("host-cgroups", "/cgroups", "Host /sys/fs/cgroups directory name mounted to container")
	containerStatsScrapeInterval = pflag.Duration("container-stats-scrape-interval", 60*time.Second, "Container resources scrape interval")

	btfPath                  = pflag.String("btf-path", "/sys/kernel/btf/vmlinux", "btf file path")
	bpfTCPSampleSeconds      = pflag.Int("bpf-net-sample-seconds", 0, "Output tcp samples each x seconds. Zero value means disabled.")
	ebpfEventsPerCPUBuffer   = pflag.Int("ebpf-events-per-cpu-buffer", os.Getpagesize()*64, "Ebpf per cpu buffer size")
	ebpfEventsOutputChanSize = pflag.Int("ebpf-events-output-queue-size", 10000, "Ebpf user spaces output channel size")

	analyzersEnabled          = pflag.Bool("analyzers-enabled", false, "Enabled analyzers")
	analyzersMinFileSizeBytes = pflag.Int64("analyzers-min-file-size-bytes", 4*1024*1024, "Analyzers min file size")
	analyzersWorkersCount     = pflag.Int("analyzers-workers-count", 2, "Analyzers workers count")

	signatureEngineInputEventChanSize  = pflag.Int("signature-engine-input-queue-size", 1000, "Input queue size for the signature engine.")
	signatureEngineOutputEventChanSize = pflag.Int("signature-engine-output-queue-size", 1000, "Output queue size for the signature engine.")

	mutedNamespaces = pflag.StringArray("mute-namespace", []string{"kube-system", "calico"}, "List of namespaces to ignore tracing events for. To mute multiple namespaces, provide this flag multiple times.")

	castaiServerInsecure = pflag.Bool("castai-server-insecure", false, "Use insecure connection to castai grpc server. Used for e2e.")

	kubeconfigPath = pflag.String("kubeconfig", "", "Kubeconfig file")
)

func NewCommand(version string) *cobra.Command {
	command := &cobra.Command{
		Use: "daemon",
		Run: func(cmd *cobra.Command, args []string) {
			pflag.Parse()

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			kubeConfig, err := getKubeConfig(*kubeconfigPath)
			if err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			}
			kubeConfig.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(float32(30), 100)
			kubeConfig.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
			kubeConfig.ContentType = "application/vnd.kubernetes.protobuf"
			clientset, err := kubernetes.NewForConfig(kubeConfig)
			if err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			}

			castaiClientCfg := castai.Config{
				APIKey:      os.Getenv("CASTAI_API_KEY"),
				APIGrpcAddr: os.Getenv("CASTAI_API_GRPC_ADDR"),
				ClusterID:   os.Getenv("CASTAI_CLUSTER_ID"),
				Insecure:    *castaiServerInsecure,
			}

			if err := app.New(&app.Config{
				LogLevel:                          *logLevel,
				LogRateInterval:                   *logRateInterval,
				LogRateBurst:                      *logRateBurst,
				SendLogsLevel:                     *sendLogLevel,
				Version:                           version,
				BTFPath:                           *btfPath,
				PyroscopeAddr:                     *pyroscopeAddr,
				IngestorAddr:                      *ingestorAddr,
				ContainerdSockPath:                *containerdSockPath,
				HostCgroupsDir:                    *hostCgroupsDir,
				HostProcDir:                       *hostProcDir,
				TCPSampleOutputMinDurationSeconds: *bpfTCPSampleSeconds,
				HTTPListenPort:                    *httpListenPort,
				State: state.Config{
					EventsSinkQueueSize:          *eventsQueueSize,
					ContainerStatsScrapeInterval: *containerStatsScrapeInterval,
					AnalyzersEnabled:             *analyzersEnabled,
				},
				EBPFEventsPerCPUBuffer:   *ebpfEventsPerCPUBuffer,
				EBPFEventsOutputChanSize: *ebpfEventsOutputChanSize,
				Analyzers: analyzers.Config{
					ContainersBasePath: *containerdK8sPath,
					MinFileSizeBytes:   *analyzersMinFileSizeBytes,
					WorkerCount:        *analyzersWorkersCount,
				},
				MutedNamespaces: *mutedNamespaces,
				SignatureEngineConfig: signature.SignatureEngineConfig{
					InputChanSize:  *signatureEngineInputEventChanSize,
					OutputChanSize: *signatureEngineOutputEventChanSize,
				},
				CastaiEnv: castaiClientCfg,
			}, clientset).Run(ctx); err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			}
		},
	}
	return command
}

func getKubeConfig(kubepath string) (*rest.Config, error) {
	if kubepath != "" {
		data, err := os.ReadFile(kubepath)
		if err != nil {
			return nil, fmt.Errorf("reading kubeconfig at %s: %w", kubepath, err)
		}
		restConfig, err := clientcmd.RESTConfigFromKubeConfig(data)
		if err != nil {
			return nil, fmt.Errorf("building rest config from kubeconfig at %s: %w", kubepath, err)
		}
		return restConfig, nil
	}

	inClusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return inClusterConfig, nil
}