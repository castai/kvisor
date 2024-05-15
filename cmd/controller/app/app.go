package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // TODO: Fix this, should not use default pprof.
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/cmd/controller/state"
	"github.com/castai/kvisor/cmd/controller/state/delta"
	"github.com/castai/kvisor/cmd/controller/state/imagescan"
	"github.com/castai/kvisor/cmd/controller/state/kubebench"
	"github.com/castai/kvisor/cmd/controller/state/kubelinter"
	"github.com/castai/kvisor/pkg/blobscache"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/go-playground/validator/v10"
	"github.com/grafana/pyroscope-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
)

type Config struct {
	// Logging configuration.
	LogLevel        string
	LogRateInterval time.Duration
	LogRateBurst    int

	// Built binary version.
	Version      string
	ChartVersion string

	// Current running pod metadata.
	PodNamespace string `validate:"required"`
	PodName      string `validate:"required"`

	// HTTPListenPort is internal http servers listen port.
	HTTPListenPort        int `validate:"required"`
	MetricsHTTPListenPort int
	KubeServerListenPort  int `validate:"required"`

	// PyroscopeAddr is optional pyroscope addr to send traces.
	PyroscopeAddr string

	CastaiController state.CastaiConfig
	CastaiEnv        castai.Config
	ImageScan        imagescan.Config
	Linter           kubelinter.Config
	KubeBench        kubebench.Config
	Delta            delta.Config
	JobsCleanup      state.JobsCleanupConfig
	AgentConfig      AgentConfig
}

type AgentConfig struct {
	Enabled bool
}

func (c Config) Proto() *castaipb.ControllerConfig {
	return &castaipb.ControllerConfig{
		LogLevel:              c.LogLevel,
		LogRateInterval:       c.LogRateInterval.String(),
		LogRateBurst:          int32(c.LogRateBurst),
		Version:               c.Version,
		ChartVersion:          c.ChartVersion,
		PodNamespace:          c.PodNamespace,
		PodName:               c.PodName,
		HttpListenPort:        int32(c.HTTPListenPort),
		MetricsHttpListenPort: int32(c.MetricsHTTPListenPort),
		PyroscopeAddr:         c.PyroscopeAddr,
		CastaiController: &castaipb.CastaiControllerConfig{
			RemoteConfigSyncDuration: c.CastaiController.RemoteConfigSyncDuration.String(),
		},
		CastaiEnv: &castaipb.CastaiConfig{
			ClusterId:   c.CastaiEnv.ClusterID,
			ApiGrpcAddr: c.CastaiEnv.APIGrpcAddr,
			Insecure:    c.CastaiEnv.Insecure,
		},
		ImageScan: &castaipb.ImageScanConfig{
			Enabled:                   c.ImageScan.Enabled,
			CastaiSecretRefName:       c.ImageScan.CastaiSecretRefName,
			ScanInterval:              c.ImageScan.ScanInterval.String(),
			ScanTimeout:               c.ImageScan.ScanTimeout.String(),
			MaxConcurrentScans:        c.ImageScan.MaxConcurrentScans,
			ScanJobImagePullPolicy:    c.ImageScan.ScanJobImagePullPolicy,
			Mode:                      c.ImageScan.Mode,
			CpuRequest:                c.ImageScan.CPURequest,
			CpuLimit:                  c.ImageScan.CPULimit,
			MemoryRequest:             c.ImageScan.MemoryRequest,
			MemoryLimit:               c.ImageScan.MemoryLimit,
			ProfileEnabled:            c.ImageScan.ProfileEnabled,
			PhlareEnabled:             c.ImageScan.PhlareEnabled,
			PrivateRegistryPullSecret: c.ImageScan.PrivateRegistryPullSecret,
			ServiceAccount:            c.ImageScan.ServiceAccount,
			InitDelay:                 c.ImageScan.InitDelay.String(),
			ImageScanBlobsCacheUrl:    c.ImageScan.ImageScanBlobsCacheURL,
		},
		Linter: &castaipb.LinterConfig{
			Enabled:      c.Linter.Enabled,
			ScanInterval: c.Linter.ScanInterval.String(),
			InitDelay:    c.Linter.InitDelay.String(),
		},
		KubeBench: &castaipb.KubeBenchConfig{
			Enabled:            c.KubeBench.Enabled,
			Force:              c.KubeBench.Force,
			ScanInterval:       c.KubeBench.ScanInterval.String(),
			JobImagePullPolicy: c.KubeBench.JobImagePullPolicy,
			CloudProvider:      c.KubeBench.CloudProvider,
			JobNamespace:       c.KubeBench.JobNamespace,
		},
		Delta: &castaipb.DeltaConfig{
			Enabled:        c.Delta.Enabled,
			Interval:       c.Delta.Interval.String(),
			InitialDeltay:  c.Delta.InitialDeltay.String(),
			SendTimeout:    c.Delta.SendTimeout.String(),
			UseCompression: c.Delta.UseCompression,
		},
		JobsCleanup: &castaipb.JobsCleanupConfig{
			CleanupInterval: c.JobsCleanup.CleanupInterval.String(),
			CleanupJobAge:   c.JobsCleanup.CleanupJobAge.String(),
			Namespace:       c.JobsCleanup.Namespace,
		},
		AgentConfig: &castaipb.ControllerAgentConfig{
			Enabled: c.AgentConfig.Enabled,
		},
	}
}

func New(cfg Config, clientset kubernetes.Interface) *App {
	if err := validator.New().Struct(cfg); err != nil {
		panic(fmt.Errorf("invalid config: %w", err).Error())
	}
	return &App{cfg: cfg, kubeClient: clientset}
}

type App struct {
	cfg Config

	kubeClient kubernetes.Interface
}

func (a *App) Run(ctx context.Context) error {
	cfg := a.cfg
	clientset := a.kubeClient

	var log *logging.Logger
	logCfg := &logging.Config{
		AddSource: true,
		Level:     logging.MustParseLevel(cfg.LogLevel),
		RateLimiter: logging.RateLimiterConfig{
			Limit:  rate.Every(cfg.LogRateInterval),
			Burst:  cfg.LogRateBurst,
			Inform: true,
		},
	}
	var castaiClient *castai.Client
	if a.cfg.CastaiEnv.Valid() {
		var err error
		castaiClient, err = castai.NewClient(fmt.Sprintf("kvisor-controller/%s", cfg.Version), cfg.CastaiEnv)
		if err != nil {
			return fmt.Errorf("setting up castai api client: %w", err)
		}
		defer castaiClient.Close()
		castaiLogsExporter := castai.NewLogsExporter(castaiClient)
		go castaiLogsExporter.Run(ctx) //nolint:errcheck
		logCfg.Export = logging.ExportConfig{
			ExportFunc: castaiLogsExporter.ExportFunc(),
			MinLevel:   slog.LevelInfo,
		}
		log = logging.New(logCfg)
	} else {
		log = logging.New(logCfg)
	}

	log.Infof("running kvisor-controller, cluster_id=%s, grpc_addr=%s, version=%s", cfg.CastaiEnv.ClusterID, cfg.CastaiEnv.APIGrpcAddr, cfg.Version)

	if cfg.PyroscopeAddr != "" {
		withPyroscope(cfg.PyroscopeAddr)
	}

	// Setup kubernetes client and watcher.
	informersFactory := informers.NewSharedInformerFactory(clientset, 0)
	k8sVersion, err := kube.GetVersion(clientset)
	if err != nil {
		return err
	}
	kubeClient := kube.NewClient(log, cfg.PodName, cfg.PodNamespace, k8sVersion, clientset)
	kubeClient.RegisterHandlers(informersFactory)

	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		return kubeClient.Run(ctx)
	})

	// CAST AI specific logic.
	if castaiClient != nil {
		errg.Go(func() error {
			castaiCtrl := state.NewCastaiController(log, cfg.CastaiController, cfg.Proto(), kubeClient, castaiClient)
			return castaiCtrl.Run(ctx)
		})

		errg.Go(func() error {
			jobsCleanupCtrl := state.NewJobsCleanupController(log, clientset, cfg.JobsCleanup)
			return jobsCleanupCtrl.Run(ctx)
		})

		if cfg.Delta.Enabled {
			deltaCtrl := delta.NewController(log, cfg.Delta, castaiClient.GRPC, kubeClient)
			kubeClient.RegisterKubernetesChangeListener(deltaCtrl)
			errg.Go(func() error {
				return deltaCtrl.Run(ctx)
			})
		}

		if cfg.ImageScan.Enabled {
			imageScanner := imagescan.NewImageScanner(clientset, cfg.ImageScan, cfg.PodNamespace)
			imageScanCtrl := imagescan.NewController(log, cfg.ImageScan, imageScanner, castaiClient.GRPC, kubeClient)
			kubeClient.RegisterKubernetesChangeListener(imageScanCtrl)
			errg.Go(func() error {
				return imageScanCtrl.Run(ctx)
			})
		}

		if cfg.Linter.Enabled {
			linter, err := kubelinter.New(lo.Keys(kubelinter.LinterRuleMap))
			if err != nil {
				return err
			}
			linterCtrl := kubelinter.NewController(log, a.cfg.Linter, linter, castaiClient.GRPC)
			kubeClient.RegisterKubernetesChangeListener(linterCtrl)
			errg.Go(func() error {
				return linterCtrl.Run(ctx)
			})
		}

		if cfg.KubeBench.Enabled {
			logsReader := kube.NewPodLogReader(clientset)
			kubeBenchCtrl := kubebench.NewController(log, clientset, a.cfg.KubeBench, castaiClient.GRPC, logsReader, kubeClient, []string{})
			kubeClient.RegisterKubernetesChangeListener(kubeBenchCtrl)
			errg.Go(func() error {
				return kubeBenchCtrl.Run(ctx)
			})
		}
	}

	errg.Go(func() error {
		return a.runHTTPServer(ctx, log)
	})

	errg.Go(func() error {
		return a.runKubeServer(ctx, log, kubeClient)
	})

	if cfg.MetricsHTTPListenPort != 0 {
		errg.Go(func() error {
			return a.runMetricsHTTPServer(ctx, log)
		})
	}

	// Kubernetes informers should start after update and delete handlers are added.
	informersFactory.Start(ctx.Done())
	informersFactory.WaitForCacheSync(ctx.Done())
	// We need to register pods informers later since they depend on deployments, daemon sets etc.
	kubeClient.RegisterPodsHandlers(informersFactory)
	informersFactory.Start(ctx.Done())
	informersFactory.WaitForCacheSync(ctx.Done())

	select {
	case <-ctx.Done():
		return waitWithTimeout(errg, 60*time.Second)
	}
}

func waitWithTimeout(errg *errgroup.Group, timeout time.Duration) error {
	errc := make(chan error, 1)
	go func() {
		errc <- errg.Wait()
	}()
	select {
	case <-time.After(timeout):
		return errors.New("timeout waiting for shutdown")
	case err := <-errc:
		return err
	}
}

func (a *App) runHTTPServer(ctx context.Context, log *logging.Logger) error {
	e := echo.New()
	e.HideBanner = true
	e.Debug = false

	e.Use(middleware.Recover())
	e.GET("/healthz", func(c echo.Context) error {
		type res struct {
			Msg string `json:"msg"`
		}
		return c.JSON(http.StatusOK, res{Msg: "Ok"})
	})

	blobsCacheSrv := blobscache.NewServer(log)
	blobsCacheSrv.RegisterHandlers(e)

	srv := http.Server{
		Addr:         fmt.Sprintf(":%d", a.cfg.HTTPListenPort),
		Handler:      e,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 1 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		log.Info("shutting down http server")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Error(err.Error())
		}
	}()
	log.Infof("running http server, port=%d", a.cfg.HTTPListenPort)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (a *App) runKubeServer(ctx context.Context, log *logging.Logger, client *kube.Client) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", a.cfg.KubeServerListenPort))
	if err != nil {
		return err
	}

	s := grpc.NewServer()
	kubepb.RegisterKubeAPIServer(s, kube.NewServer(client))

	go func() {
		<-ctx.Done()
		log.Info("shutting kube grpc server")
		s.GracefulStop()
	}()
	log.Infof("running kube server, port=%d", a.cfg.KubeServerListenPort)
	if err := s.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

func (a *App) runMetricsHTTPServer(ctx context.Context, log *logging.Logger) error {
	e := echo.New()
	e.HideBanner = true
	e.Debug = false

	e.Use(middleware.Recover())
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))
	e.GET("/debug/pprof/*item", echo.WrapHandler(http.DefaultServeMux))
	srv := http.Server{
		Addr:         fmt.Sprintf(":%d", a.cfg.MetricsHTTPListenPort),
		Handler:      e,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 1 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		log.Info("shutting metrics down http server")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Error(err.Error())
		}
	}()
	log.Infof("running metrics server, port=%d", a.cfg.MetricsHTTPListenPort)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func withPyroscope(addr string) {
	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "kvisor-controller",
		ServerAddress:   addr,
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileInuseObjects,
			pyroscope.ProfileInuseSpace,
			pyroscope.ProfileGoroutines,
		},
	}); err != nil {
		panic(err)
	}
}
