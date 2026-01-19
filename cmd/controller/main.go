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

	"github.com/castai/kvisor/cmd/controller/config"
	"github.com/castai/kvisor/cmd/controller/controllers/imagescan"
	"github.com/castai/kvisor/cmd/controller/controllers/kubebench"
	"github.com/castai/kvisor/cmd/controller/controllers/kubelinter"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"

	"github.com/castai/kvisor/cmd/controller/app"
	"github.com/castai/kvisor/cmd/controller/controllers"
)

var (
	Version = "local"

	kubeconfigPath        = pflag.String("kubeconfig", "", "Kubeconfig file")
	metricsHTTPListenPort = pflag.Int("metrics-http-listen-port", 6060, "metrics http listen port")
	serverHTTPListenPort  = pflag.Int("http-listen-port", 8080, "server http listen port")
	kubeServerListenPort  = pflag.Int("kube-server-listen-port", 8090, "kube server grpc http listen port")

	logLevel                  = pflag.String("log-level", slog.LevelDebug.String(), "Log level")
	logRateInterval           = pflag.Duration("log-rate-interval", 100*time.Millisecond, "Log rate limit interval")
	logRateBurst              = pflag.Int("log-rate-burst", 100, "Log rate burst")
	promMetricsExportEnabled  = pflag.Bool("prom-metrics-export-enabled", false, "Enabled sending internal prometheus metrics")
	promMetricsExportInterval = pflag.Duration("prom-metrics-export-interval", 5*time.Minute, "Internal prometheus metrics export interval")

	chartVersion = pflag.String("chart-version", "", "Helm chart version")

	cloudProvider                = pflag.String("cloud-provider", "", "Cloud provider in which the cluster is running")
	cloudProviderVPCSyncEnabled  = pflag.Bool("cloud-provider-vpc-sync-enabled", false, "Enable cloud provider VPC metadata sync")
	cloudProviderVPCName         = pflag.String("cloud-provider-vpc-name", "", "Cloud provider VPC name in which the cluster is running")
	cloudProviderVPCSyncInterval = pflag.Duration("cloud-provider-vpc-sync-interval", 1*time.Hour, "Cloud provider VPC sync interval")
	cloudProviderVPCCacheSize    = pflag.Uint32("cloud-provider-vpc-cache-size", 10000, "Cloud provider VPC cache size")
	cloudProviderGCPProjectID    = pflag.String("cloud-provider-gcp-project-id", "", "Cloud provider VPC syncer in which the cluster is running")

	castaiSecretRefName      = pflag.String("castai-secret-ref-name", "castai-kvisor", "CASTAI k8s secret name")
	castaiConfigSyncDuration = pflag.Duration("castai-config-sync-duration", 1*time.Minute, "CASTAI remote config sync duration")
	castaiServerInsecure     = pflag.Bool("castai-server-insecure", false, "Use insecure connection to castai grpc server. Used for e2e.")

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
	imageScanIgnoredNamespaces     = pflag.StringSlice("image-scan-ignored-namespaces", []string{},
		"Image scan ignored namespaces. For example: --image-scan-ignored-namespaces=kube-system,my-namespace")
	imageScanDisabledAnalyzers = pflag.StringSlice("image-scan-disabled-analyzers", []string{"secret"},
		"Image scan disabled scanners. For example: image-scan-disabled-analyzers=secret") // secret analyzer is disabled by default for performance reasons, see https://github.com/castai/kvisor/pull/343

	kubeBenchEnabled            = pflag.Bool("kube-bench-enabled", false, "Kube Bench enabled")
	kubeBenchScanInterval       = pflag.Duration("kube-bench-scan-interval", 5*time.Minute, "Kube bench scan interval")
	kubeBenchForceScan          = pflag.Bool("kube-bench-force", false, "Kube Bench force scan")
	kubeBenchJobImagePullPolicy = pflag.String("kube-bench-job-pull-policy", "IfNotPresent", "Kube bench job image pull policy")
	// deprecated: use cloudProvider
	kubeBenchCloudProvider = pflag.String("kube-bench-cloud-provider", "", "Kube bench cloud provider. Deprecated: use `cloud-provider` instead.")

	kubeLinterEnabled      = pflag.Bool("kube-linter-enabled", false, "Kube linter enabled")
	kubeLinterScanInterval = pflag.Duration("kube-linter-scan-interval", 60*time.Second, "Kube linter scan interval")
	kubeLinterInitDelay    = pflag.Duration("kube-linter-init-delay", 60*time.Second, "Kube linter init delay")

	jobsCleanupInterval = pflag.Duration("jobs-cleanup", 10*time.Minute, "Jobs cleanup interval")
	jobsCleanupJobAge   = pflag.Duration("jobs-cleanup-job-age", 10*time.Minute, "Jobs cleanup job age")

	agentEnabled = pflag.Bool("agent-enabled", false, "Whether kvisor-agent is enabled (used for reporting; does not enable agent)")
)

func main() {
	pflag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	castaiClientCfg, err := castai.NewConfigFromEnv(*castaiServerInsecure)
	if err != nil {
		slog.Warn(fmt.Errorf("failed to initialize CAST AI client config: %w", err).Error())
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

	var cloudProviderVal string
	if *cloudProvider != "" {
		cloudProviderVal = *cloudProvider
	} else {
		slog.Warn(`--kube-bench-cloud-provider is deprecated, please use --cloud-provider instead.`)
		cloudProviderVal = *kubeBenchCloudProvider
	}

	podNs := os.Getenv("POD_NAMESPACE")
	if podNs == "" {
		podNs = "localenv"
	}
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		podName = "localenv"
	}
	appInstance := app.New(config.Config{
		LogLevel:                  *logLevel,
		LogRateInterval:           *logRateInterval,
		LogRateBurst:              *logRateBurst,
		PromMetricsExportEnabled:  *promMetricsExportEnabled,
		PromMetricsExportInterval: *promMetricsExportInterval,
		PodName:                   podName,
		PodNamespace:              podNs,
		Version:                   Version,
		ChartVersion:              *chartVersion,
		MetricsHTTPListenPort:     *metricsHTTPListenPort,
		HTTPListenPort:            *serverHTTPListenPort,
		KubeServerListenPort:      *kubeServerListenPort,
		CastaiEnv:                 castaiClientCfg,
		CastaiController: controllers.CastaiConfig{
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
			CastaiGRPCAddress:         castaiClientCfg.APIGrpcAddr,
			CastaiClusterID:           castaiClientCfg.ClusterID,
			CastaiGrpcInsecure:        *castaiServerInsecure,
			ImageScanBlobsCacheURL:    *imageScanBlobsCacheURL,
			CloudProvider:             cloudProviderVal,
			IgnoredNamespaces:         *imageScanIgnoredNamespaces,
			DisabledAnalyzers:         *imageScanDisabledAnalyzers,
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
			CloudProvider:      cloudProviderVal,
			JobNamespace:       podNs,
		},
		JobsCleanup: controllers.JobsCleanupConfig{
			CleanupInterval: *jobsCleanupInterval,
			CleanupJobAge:   *jobsCleanupJobAge,
			Namespace:       podNs,
		},
		AgentConfig: config.AgentConfig{
			Enabled: *agentEnabled,
		},
		CloudProvider: controllers.VPCMetadataConfig{
			Enabled:         *cloudProviderVPCSyncEnabled,
			NetworkName:     *cloudProviderVPCName,
			RefreshInterval: *cloudProviderVPCSyncInterval,
			CacheSize:       *cloudProviderVPCCacheSize,
			Type:            *cloudProvider,
			GCPProjectID:    *cloudProviderGCPProjectID,
		},
	},
		clientset,
	)

	if err := appInstance.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
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
