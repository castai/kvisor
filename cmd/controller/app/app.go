package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // TODO: Fix this, should not use default pprof.
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/cmd/controller/state"
	"github.com/castai/kvisor/cmd/controller/state/imagescan"
	"github.com/castai/kvisor/cmd/controller/state/kubebench"
	"github.com/castai/kvisor/cmd/controller/state/kubelinter"
	"github.com/castai/kvisor/pkg/blobscache"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus"
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

		if a.cfg.PromMetricsExportEnabled {
			castaiMetricsExporter := castai.NewPromMetricsExporter(log, castaiLogsExporter, prometheus.DefaultGatherer, castai.PromMetricsExporterConfig{
				PodName:        a.cfg.PodName,
				ExportInterval: a.cfg.PromMetricsExportInterval,
			})
			go castaiMetricsExporter.Run(ctx) //nolint:errcheck
		}

		logCfg.Export = logging.ExportConfig{
			ExportFunc: castaiLogsExporter.ExportFunc(),
			MinLevel:   slog.LevelInfo,
		}
		log = logging.New(logCfg)
	} else {
		log = logging.New(logCfg)
	}

	log.Infof("running kvisor-controller, cluster_id=%s, grpc_addr=%s, version=%s", cfg.CastaiEnv.ClusterID, cfg.CastaiEnv.APIGrpcAddr, cfg.Version)

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
			jsonConfig, err := json.Marshal(a.cfg) //nolint:musttag
			if err != nil {
				return fmt.Errorf("marshaling config: %w", err)
			}

			castaiCtrl := state.NewCastaiController(log, cfg.CastaiController, jsonConfig, kubeClient, castaiClient)
			return castaiCtrl.Run(ctx)
		})

		errg.Go(func() error {
			jobsCleanupCtrl := state.NewJobsCleanupController(log, clientset, cfg.JobsCleanup)
			return jobsCleanupCtrl.Run(ctx)
		})

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
