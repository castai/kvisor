package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"time"

	"github.com/castai/kvisor/cmd/agent/daemon/conntrack"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/cmd/agent/daemon/netstats"
	"github.com/castai/kvisor/cmd/agent/daemon/state"
	"github.com/castai/kvisor/cmd/agent/kube"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/go-playground/validator/v10"
	"github.com/grafana/pyroscope-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/client-go/kubernetes"

	"github.com/castai/kvisor/pkg/containers"
)

type Config struct {
	LogLevel                          string
	LogRateInterval                   time.Duration
	LogRateBurst                      int
	SendLogsLevel                     string
	Version                           string
	BTFPath                           string
	PyroscopeAddr                     string
	IngestorAddr                      string
	ContainerdSockPath                string
	HostCgroupsDir                    string
	TCPSampleOutputMinDurationSeconds int
	MetricsHTTPListenPort             int
	State                             state.Config
	EBPFEventsPerCPUBuffer            int `validate:"required"`
	EBPFEventsOutputChanSize          int `validate:"required"`
	MutedNamespaces                   []string
	SignatureEngineConfig             signature.SignatureEngineConfig
	CastaiEnv                         castai.Config
	EnricherConfig                    EnricherConfig
	ContainerPreFetchEnabled          bool
}

type EnricherConfig struct {
	EnableFileHashEnricher bool
}

func New(cfg *Config, clientset kubernetes.Interface) *App {
	if err := validator.New().Struct(cfg); err != nil {
		panic(fmt.Errorf("invalid config: %w", err).Error())
	}
	return &App{cfg: cfg, kubeClient: clientset}
}

type App struct {
	cfg *Config

	kubeClient kubernetes.Interface
}

func (a *App) Run(ctx context.Context) error {
	// TODO: Enable compression and test perf impact.
	ingestorClientRetryPolicy := `{
            "methodConfig": [{
                "waitForReady": true,
                "retryPolicy": {
                    "MaxAttempts": 4,
                    "InitialBackoff": ".01s",
                    "MaxBackoff": ".01s",
                    "BackoffMultiplier": 1.0,
                    "RetryableStatusCodes": [ "UNAVAILABLE" ]
                }
            }]
        }`

	cfg := a.cfg
	castaiClient, err := castai.NewClient(fmt.Sprintf("kvisor-agent/%s", cfg.Version), cfg.CastaiEnv)
	if err != nil {
		return fmt.Errorf("setting up castai api client: %w", err)
	}
	apiConn, err := grpc.Dial(
		a.cfg.IngestorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(ingestorClientRetryPolicy),
	)
	if err != nil {
		return fmt.Errorf("api server dial: %w", err)
	}
	defer apiConn.Close()

	logCfg := &logging.Config{
		Level:     logging.MustParseLevel(a.cfg.LogLevel),
		AddSource: true,
		RateLimiter: logging.RateLimiterConfig{
			Limit:  rate.Every(a.cfg.LogRateInterval),
			Burst:  a.cfg.LogRateBurst,
			Inform: true,
		},
	}
	if a.cfg.SendLogsLevel != "" {
		castaiLogsExporter := castai.NewLogsExporter(castaiClient)
		go castaiLogsExporter.Run(ctx) //nolint:errcheck

		logCfg.Export = logging.ExportConfig{
			ExportFunc: castaiLogsExporter.ExportFunc(),
			MinLevel:   logging.MustParseLevel(a.cfg.SendLogsLevel),
		}
	}
	log := logging.New(logCfg)
	log.Infof("running kvisord agent, version=%s", a.cfg.Version)
	defer log.Infof("stopping kvisord agent, version=%s", a.cfg.Version)

	if addr := a.cfg.PyroscopeAddr; addr != "" {
		withPyroscope(addr)
	}

	cgroupClient, err := cgroup.NewClient(log, a.cfg.HostCgroupsDir)
	if err != nil {
		return err
	}
	containersClient, err := containers.NewClient(log, cgroupClient, a.cfg.ContainerdSockPath)
	if err != nil {
		return err
	}

	containersInitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = containersClient.Init(containersInitCtx, a.cfg.ContainerPreFetchEnabled)
	if err != nil {
		return fmt.Errorf("containers client init: %w", err)
	}

	ct, err := conntrack.NewClient(log)
	if err != nil {
		return fmt.Errorf("conntrack: %w", err)
	}
	defer ct.Close()

	activeSignatures := signature.DefaultSignatures(log, a.cfg.SignatureEngineConfig.DefaultSignatureConfig)

	signatureEngine := signature.NewEngine(activeSignatures, log, a.cfg.SignatureEngineConfig)

	procHandler := proc.New()
	mountNamespacePIDStore, err := getInitializedMountNamespaceStore(procHandler)
	if err != nil {
		return fmt.Errorf("mount namespace PID store: %w", err)
	}

	enrichmentService := enrichment.NewService(log, enrichment.Config{
		WorkerCount:    runtime.NumCPU(),
		EventEnrichers: getActiveEnrichers(a.cfg.EnricherConfig, log, mountNamespacePIDStore),
	})

	pidNSID, err := procHandler.GetCurrentPIDNSID()
	if err != nil {
		return fmt.Errorf("proc handler: %w", err)
	}

	tracer := ebpftracer.New(log, ebpftracer.Config{
		BTFPath:                 a.cfg.BTFPath,
		EventsPerCPUBuffer:      a.cfg.EBPFEventsPerCPUBuffer,
		EventsOutputChanSize:    a.cfg.EBPFEventsOutputChanSize,
		DefaultCgroupsVersion:   cgroupClient.DefaultCgroupVersion().String(),
		ActualDestinationGetter: ct,
		ContainerClient:         containersClient,
		CgroupClient:            cgroupClient,
		EnrichEvent:             enrichmentService.Enqueue,
		MountNamespacePIDStore:  mountNamespacePIDStore,
		HomePIDNS:               pidNSID,
	})
	if err := tracer.Load(); err != nil {
		return fmt.Errorf("loading tracer: %w", err)
	}
	policy := &ebpftracer.Policy{
		SignatureEngine: signatureEngine,
		SystemEvents: []events.ID{
			events.SignalCgroupMkdir,
			events.SignalCgroupRmdir,
		},
		Events: []*ebpftracer.EventPolicy{
			{ID: events.SchedProcessExec},
			{
				ID: events.SockSetState,
				PreFilterGenerator: ebpftracer.PreRateLimit(ebpftracer.RateLimitPolicy{
					Rate:  5,
					Burst: 1,
				}),
			},
			{
				ID: events.NetPacketDNSBase,
				FilterGenerator: ebpftracer.FilterAnd(
					ebpftracer.FilterEmptyDnsAnswers(log),
					ebpftracer.DeduplicateDnsEvents(log, 100, 60*time.Second),
				),
			},
			{ID: events.TrackSyscallStats},
			{
				ID: events.FileModification,
				PreFilterGenerator: ebpftracer.PreRateLimit(ebpftracer.RateLimitPolicy{
					Interval: 15 * time.Second,
				}),
			},
			{ID: events.ProcessOomKilled}, // OOM events should not happen too often and we want to know about all of them
			{ID: events.MagicWrite},
		},
	}
	// TODO: Allow to change policy on the fly. We should be able to change it from remote config.
	if err := tracer.ApplyPolicy(policy); err != nil {
		return fmt.Errorf("apply policy: %w", err)
	}

	netStatsReader := netstats.NewReader(proc.Path)

	nodeName, found := os.LookupEnv("NODE_NAME")
	if !found {
		return errors.New("missing `NODE_NAME` environment variable")
	}

	kubeClient := kube.NewClient(log, a.kubeClient, nodeName)

	ctrl := state.NewController(
		log,
		a.cfg.State,
		castaiClient,
		containersClient,
		netStatsReader,
		ct,
		tracer,
		signatureEngine,
		enrichmentService,
		kubeClient,
	)

	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		return a.runHTTPServer(ctx, log)
	})

	errg.Go(func() error {
		return tracer.Run(ctx)
	})

	errg.Go(func() error {
		return signatureEngine.Run(ctx)
	})

	errg.Go(func() error {
		return ctrl.Run(ctx)
	})

	errg.Go(func() error {
		return kubeClient.Run(ctx)
	})

	errg.Go(func() error {
		return enrichmentService.Run(ctx)
	})

	for _, namespace := range a.cfg.MutedNamespaces {
		err := ctrl.MuteNamespace(namespace)
		if err != nil {
			log.Warnf("error while muting namespace: %v", err)
		}
	}

	select {
	case <-ctx.Done():
		return waitWithTimeout(errg, 10*time.Second)
	}
}

func getActiveEnrichers(cfg EnricherConfig, log *logging.Logger, mountNamespacePIDStore *types.PIDsPerNamespace) []enrichment.EventEnricher {
	var result []enrichment.EventEnricher

	if cfg.EnableFileHashEnricher {
		result = append(result, enrichment.EnrichWithFileHash(log, mountNamespacePIDStore, proc.GetFS()))
	}

	return result
}

func getInitializedMountNamespaceStore(procHandler *proc.Proc) (*types.PIDsPerNamespace, error) {
	mountNamespacePIDStore, err := types.NewPIDsPerNamespaceCache(2048, 5)
	if err != nil {
		return nil, err
	}

	processes, err := procHandler.LoadMountNSOldestProcesses()
	if err != nil {
		return nil, err
	}

	for ns, pid := range processes {
		mountNamespacePIDStore.ForceAddToBucket(ns, pid)
	}

	return mountNamespacePIDStore, nil
}

func (a *App) runHTTPServer(ctx context.Context, log *logging.Logger) error {
	log.Info("running http server")
	defer log.Info("stopping http server")

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := http.Server{
		Addr:         fmt.Sprintf(":%d", a.cfg.MetricsHTTPListenPort),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 1 * time.Minute,
	}

	go func() {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http serve: %w", err)
	}

	return nil
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

func withPyroscope(addr string) {
	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "kvisor-agent",
		ServerAddress:   addr,
		Tags: map[string]string{
			"pod": os.Getenv("POD_NAME"),
		},
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
