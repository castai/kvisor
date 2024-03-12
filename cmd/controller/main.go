package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/castai/kvisor/cmd/controller/state/delta"
	"github.com/castai/kvisor/cmd/controller/state/imagescan"
	"github.com/castai/kvisor/cmd/controller/state/kubebench"
	"github.com/castai/kvisor/cmd/controller/state/kubelinter"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"

	"github.com/castai/kvisor/cmd/controller/app"
	"github.com/castai/kvisor/cmd/controller/state"
)

var (
	Version = "local"

	kubeconfigPath = pflag.String("kubeconfig", "", "Kubeconfig file")
	httpListenPort = pflag.Int("http-listen-port", 6060, "server listen port")

	logLevel        = pflag.String("log-level", slog.LevelDebug.String(), "Log level")
	logRateInterval = pflag.Duration("log-rate-iterval", 100*time.Millisecond, "Log rate limit interval")
	logRateBurst    = pflag.Int("log-rate-burst", 100, "Log rate burst")

	pyroscopeAddr = pflag.String("pyroscope-addr", "", "Enable pyroscope tracing")

	agentDaemonSetName = pflag.String("agent-daemonset-name", "", "Agent DaemonSet name")

	castaiSecretRefName      = pflag.String("castai-secret-ref-name", "castai-kvisor", "CASTAI k8s secret name")
	castaiConfigSyncDuration = pflag.Duration("castai-config-sync-duration", 1*time.Minute, "CASTAI remote config sync duration")
	castaiServerInsecure     = pflag.Bool("castai-server-insecure", false, "Use insecure connection to castai grpc server. Used for e2e.")

	kubernetesDeltaEnabled            = pflag.Bool("kubernetes-delta-enabled", true, "Enable kubernetes delta sync")
	kubernetesDeltaReportInterval     = pflag.Duration("kubernetes-delta-interval", 15*time.Second, "Interval to report kubernetes object changes to cast backend (default `15s`, set to `0s` to disable)")
	initialKubernetesDeltaReportDelay = pflag.Duration("kubernetes-delta-init-delay", 60*time.Second, "Initial delay to wait before starting reporting first kubernetes object deltas (first send report is full snapshot, this might take some time for large clusters. default: `1m`)")
	kubernetesDeltaSendTimeout        = pflag.Duration("kubernetes-delta-send-timeout", 3*time.Minute, "Kubernetes deltas send timeout")

	imageScanEnabled               = pflag.Bool("image-scan-enabled", false, "Enable image scanning")
	imageScanInterval              = pflag.Duration("image-scan-interval", 30*time.Second, "Image scan scheduling interval")
	imageScanTimeout               = pflag.Duration("image-scan-timeout", 10*time.Minute, "Image scan timeout")
	imageConcurrentScans           = pflag.Int64("image-concurrent-scans", 1, "Image concurrent scans")
	imageScanMode                  = pflag.String("image-scan-mode", "remote", "Image scan mode")
	imageScanJobImagePullPolicy    = pflag.String("image-scan-job-pull-policy", "IfNotPresent", "Image scan job image pull policy")
	imageScanInitDelay             = pflag.Duration("image-scan-init-delay", 60*time.Second, "Image scan init delay")
	imagePrivateRegistryPullSecret = pflag.String("image-private-registry-pull-secret", "", "Image private registry pull secret")
	imageScanServiceAccount        = pflag.String("image-scan-service-account", "", "Image scan job kubernetes service account. Useful for IAM based private registry auth.")
	imageScanCPURequest            = pflag.String("image-scan-cpu-request", "1m", "Image scan cpu request")
	imageScanCPULimit              = pflag.String("image-scan-cpu-limit", "2", "Image scan cpu limit")
	imageScanMemoryRequest         = pflag.String("image-scan-memory-request", "1Mi", "Image scan memory request")
	imageScanMemoryLimit           = pflag.String("image-scan-memory-limit", "2Gi", "Image scan memory limit")
	imageScanProfileProfileEnabled = pflag.Bool("image-profile-enabled", false, "Image scan pprof and pyroscope")
	imageScanBlobsCacheURL         = pflag.String("image-scan-blobs-cache-url", "http://castai-kvisor-controller.castai-agent", "Image scan blobs cache server url")

	kubeBenchEnabled            = pflag.Bool("kube-bench-enabled", false, "Kube Bench enabled")
	kubeBenchScanInterval       = pflag.Duration("kube-bench-scan-interval", 5*time.Minute, "Kube bench scan interval")
	kubeBenchForceScan          = pflag.Bool("kube-bench-force", false, "Kube Bench force scan")
	kubeBenchJobImagePullPolicy = pflag.String("kube-bench-job-pull-policy", "IfNotPresent", "Kube bench job image pull policy")
	kubeBenchCloudProvider      = pflag.String("kube-bench-cloud-provider", "", "Kube bench cloud provider")

	kubeLinterEnabled      = pflag.Bool("kube-linter-enabled", false, "Kube linter enabled")
	kubeLinterScanInterval = pflag.Duration("kube-linter-scan-interval", 60*time.Second, "Kube linter scan interval")
	kubeLinterInitDelay    = pflag.Duration("kube-linter-init-delay", 60*time.Second, "Kube linter init delay")

	jobsCleanupInterval = pflag.Duration("jobs-cleanup", 10*time.Minute, "Jobs cleanup interval")
	jobsCleanupJobAge   = pflag.Duration("jobs-cleanup-job-age", 10*time.Minute, "Jobs cleanup job age")
)

func main() {
	pflag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	castaiClientCfg := castai.Config{
		APIKey:      os.Getenv("CASTAI_API_KEY"),
		APIGrpcAddr: os.Getenv("CASTAI_API_GRPC_ADDR"),
		ClusterID:   os.Getenv("CASTAI_CLUSTER_ID"),
		Insecure:    *castaiServerInsecure,
	}

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

	podNs := os.Getenv("POD_NAMESPACE")
	appInstance := app.New(&app.Config{
		LogLevel:           *logLevel,
		LogRateInterval:    *logRateInterval,
		LogRateBurst:       *logRateBurst,
		PodNamespace:       podNs,
		AgentDaemonSetName: *agentDaemonSetName,
		Version:            Version,
		PyroscopeAddr:      *pyroscopeAddr,
		HTTPListenPort:     *httpListenPort,
		CastaiEnv:          castaiClientCfg,
		CastaiController: state.CastaiConfig{
			RemoteConfigSyncDuration: *castaiConfigSyncDuration,
		},
		ImageScan: imagescan.Config{
			Enabled:                   *imageScanEnabled,
			CastaiSecretRefName:       *castaiSecretRefName,
			ScanInterval:              *imageScanInterval,
			ScanTimeout:               *imageScanTimeout,
			MaxConcurrentScans:        *imageConcurrentScans,
			ScanJobImagePullPolicy:    *imageScanJobImagePullPolicy,
			Mode:                      *imageScanMode,
			CPURequest:                *imageScanCPURequest,
			CPULimit:                  *imageScanCPULimit,
			MemoryRequest:             *imageScanMemoryRequest,
			MemoryLimit:               *imageScanMemoryLimit,
			ProfileEnabled:            *imageScanProfileProfileEnabled,
			PhlareEnabled:             *imageScanProfileProfileEnabled,
			PrivateRegistryPullSecret: *imagePrivateRegistryPullSecret,
			ServiceAccount:            *imageScanServiceAccount,
			InitDelay:                 *imageScanInitDelay,
			CastaiGrpcInsecure:        *castaiServerInsecure,
			ImageScanBlobsCacheURL:    *imageScanBlobsCacheURL,
		},
		Linter: kubelinter.Config{
			Enabled:      *kubeLinterEnabled,
			ScanInterval: *kubeLinterScanInterval,
			InitDelay:    *kubeLinterInitDelay,
		},
		KubeBench: kubebench.Config{
			Enabled:            *kubeBenchEnabled,
			Force:              *kubeBenchForceScan,
			ScanInterval:       *kubeBenchScanInterval,
			JobImagePullPolicy: *kubeBenchJobImagePullPolicy,
			CloudProvider:      *kubeBenchCloudProvider,
			JobNamespace:       podNs,
		},
		Delta: delta.Config{
			Enabled:       *kubernetesDeltaEnabled,
			Interval:      *kubernetesDeltaReportInterval,
			InitialDeltay: *initialKubernetesDeltaReportDelay,
			SendTimeout:   *kubernetesDeltaSendTimeout,
		},
		JobsCleanup: state.JobsCleanupConfig{
			CleanupInterval: *jobsCleanupInterval,
			CleanupJobAge:   *jobsCleanupJobAge,
			Namespace:       podNs,
		},
	},
		clientset,
	)

	if err := appInstance.Run(ctx); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
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
