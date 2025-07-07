package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	kubepb "github.com/castai/kvisor/api/v1/kube"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/config"
	"github.com/castai/kvisor/cmd/agent/daemon/conntrack"
	"github.com/castai/kvisor/cmd/agent/daemon/cri"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/cmd/agent/daemon/export"
	castaiexport "github.com/castai/kvisor/cmd/agent/daemon/export/castai"
	clickhouseexport "github.com/castai/kvisor/cmd/agent/daemon/export/clickhouse"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/cmd/agent/daemon/netstats"
	"github.com/castai/kvisor/cmd/agent/daemon/pipeline"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/kernel"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/go-playground/validator/v10"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func New(cfg *config.Config) *App {
	if err := validator.New().Struct(cfg); err != nil {
		panic(fmt.Errorf("invalid config: %w", err).Error())
	}
	return &App{cfg: cfg}
}

type App struct {
	cfg *config.Config
}

func (a *App) Run(ctx context.Context) error {
	start := time.Now()

	cfg := a.cfg
	logCfg := &logging.Config{
		Level:     logging.MustParseLevel(a.cfg.LogLevel),
		AddSource: true,
		RateLimiter: logging.RateLimiterConfig{
			Limit:  rate.Every(a.cfg.LogRateInterval),
			Burst:  a.cfg.LogRateBurst,
			Inform: true,
		},
	}

	podName := os.Getenv("POD_NAME")

	var log *logging.Logger
	var exporters []export.DataBatchWriter
	// Castai specific spetup if config is valid.
	if cfg.Castai.Valid() {
		castaiClient, err := castai.NewClient(fmt.Sprintf("kvisor-agent/%s", cfg.Version), cfg.Castai)
		if err != nil {
			return fmt.Errorf("setting up castai api client: %w", err)
		}
		if err := a.syncRemoteConfig(ctx, castaiClient); err != nil {
			return fmt.Errorf("sync remote config: %w", err)
		}
		if cfg.SendLogsLevel != "" {
			castaiLogsExporter := castai.NewLogsExporter(castaiClient)
			go castaiLogsExporter.Run(ctx) //nolint:errcheck

			if cfg.PromMetricsExportEnabled {
				castaiMetricsExporter := castai.NewPromMetricsExporter(log, castaiLogsExporter, prometheus.DefaultGatherer, castai.PromMetricsExporterConfig{
					PodName:        podName,
					ExportInterval: cfg.PromMetricsExportInterval,
				})
				go castaiMetricsExporter.Run(ctx) //nolint:errcheck
			}

			logCfg.Export = logging.ExportConfig{
				ExportFunc: castaiLogsExporter.ExportFunc(),
				MinLevel:   logging.MustParseLevel(cfg.SendLogsLevel),
			}
		}
		log = logging.New(logCfg)

		exporters = append(exporters, castaiexport.NewDataBatchWriter(castaiClient, log))

	} else {
		log = logging.New(logCfg)
		log.Warn("castai config is not set or it is invalid, running agent in standalone mode")
	}

	kernelVersion, _ := kernel.CurrentKernelVersion()
	log.Infof("starting kvisor agent, version=%s, kernel_version=%s", cfg.Version, kernelVersion)

	kubeAPIServiceConn, err := grpc.NewClient(
		cfg.KubeAPIServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("kube api service grpc server dial: %w", err)
	}
	defer kubeAPIServiceConn.Close()
	kubeAPIServerClient := kubepb.NewKubeAPIClient(kubeAPIServiceConn)

	if cfg.Clickhouse.Addr != "" {
		storageConn, err := clickhouse.Open(&clickhouse.Options{
			Addr: []string{cfg.Clickhouse.Addr},
			Auth: clickhouse.Auth{
				Database: cfg.Clickhouse.Database,
				Username: cfg.Clickhouse.Username,
				Password: cfg.Clickhouse.Password,
			},
			Settings: clickhouse.Settings{
				"allow_experimental_object_type": "1",
			},
			MaxOpenConns: 20,
		})
		if err != nil {
			return err
		}
		defer storageConn.Close()

		exporters = append(exporters, clickhouseexport.NewDataBatchWriter(storageConn))
	}

	if len(exporters) == 0 {
		return errors.New("no configured exporters")
	}

	procHandler := proc.New()

	cgroupClient, err := cgroup.NewClient(log, cfg.HostCgroupsDir, procHandler.PSIEnabled())
	if err != nil {
		return err
	}

	criClient, criCloseFn, err := cri.NewRuntimeClient(ctx, cfg.CRIEndpoint)
	if err != nil {
		return fmt.Errorf("new CRI runtime client: %w", err)
	}
	defer criCloseFn() //nolint:errcheck

	containersClient, err := containers.NewClient(log, cgroupClient, cfg.ContainerdSockPath, procHandler, criClient, cfg.EventLabels, cfg.EventAnnotations)
	if err != nil {
		return err
	}
	defer containersClient.Close()

	processTreeCollector := processtree.New(log, procHandler, containersClient)

	ct, err := conntrack.NewClient(log)
	if err != nil {
		return fmt.Errorf("conntrack: %w", err)
	}
	defer ct.Close()

	activeSignatures, err := signature.DefaultSignatures(log, cfg.SignatureEngineConfig)
	if err != nil {
		return fmt.Errorf("error while configuring signatures: %w", err)
	}
	signatureEngine := signature.NewEngine(activeSignatures, log, cfg.SignatureEngineConfig)

	mountNamespacePIDStore, err := getInitializedMountNamespaceStore(procHandler)
	if err != nil {
		return fmt.Errorf("mount namespace PID store: %w", err)
	}

	enrichmentService := enrichment.NewService(log, enrichment.Config{
		WorkerCount:    int(math.Min(float64(runtime.NumCPU()), 4)), // Cap to max 4 enrichment goroutines.
		EventEnrichers: getActiveEnrichers(cfg.EnricherConfig, log, mountNamespacePIDStore),
	})

	pidNSID, err := procHandler.GetCurrentPIDNSID()
	if err != nil {
		return fmt.Errorf("proc handler: %w", err)
	}

	if cfg.EBPFMetrics.ProgramMetricsEnabled {
		cleanup := enableBPFStats(cfg, log)
		defer cleanup()
	}

	tracer := ebpftracer.New(log, ebpftracer.Config{
		FileAccessEnabled:          cfg.FileAccess.Enabled,
		BTFPath:                    cfg.BTFPath,
		SignalEventsRingBufferSize: cfg.EBPFSignalEventsRingBufferSize,
		EventsRingBufferSize:       cfg.EBPFEventsRingBufferSize,
		SkbEventsRingBufferSize:    cfg.EBPFSkbEventsRingBufferSize,
		EventsOutputChanSize:       cfg.EBPFEventsOutputChanSize,
		DefaultCgroupsVersion:      cgroupClient.DefaultCgroupVersion().String(),
		ContainerClient:            containersClient,
		CgroupClient:               cgroupClient,
		AutomountCgroupv2:          cfg.AutomountCgroupv2,
		SignatureEngine:            signatureEngine,
		MountNamespacePIDStore:     mountNamespacePIDStore,
		HomePIDNS:                  pidNSID,
		NetflowsEnabled:            cfg.Netflow.Enabled,
		NetflowGrouping:            cfg.Netflow.Grouping,
		MetricsReporting: ebpftracer.MetricsReportingConfig{
			ProgramMetricsEnabled: cfg.EBPFMetrics.ProgramMetricsEnabled,
			TracerMetricsEnabled:  cfg.EBPFMetrics.TracerMetricsEnabled,
		},
		PodName: podName,
	})
	if err := tracer.Load(); err != nil {
		return fmt.Errorf("loading tracer: %w", err)
	}
	defer tracer.Close()

	policy := buildEBPFPolicy(log, cfg, signatureEngine)
	// TODO: Allow to change policy on the fly. We should be able to change it from remote config.
	if err := tracer.ApplyPolicy(policy); err != nil {
		return fmt.Errorf("apply policy: %w", err)
	}

	netStatsReader := netstats.NewReader(proc.Path)

	ctrl := pipeline.NewController(
		log,
		pipeline.Config{
			Netflow:     cfg.Netflow,
			Events:      cfg.Events,
			Stats:       cfg.Stats,
			ProcessTree: cfg.ProcessTree,
			DataBatch:   cfg.DataBatch,
		},
		exporters,
		containersClient,
		netStatsReader,
		ct,
		tracer,
		signatureEngine,
		kubeAPIServerClient,
		processTreeCollector,
		procHandler,
		enrichmentService,
	)

	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		return a.runHTTPServer(ctx, log)
	})

	errg.Go(func() error {
		return signatureEngine.Run(ctx)
	})

	errg.Go(func() error {
		return ctrl.Run(ctx)
	})

	errg.Go(func() error {
		return enrichmentService.Run(ctx)
	})

	// Tracer should not run in err group because it can block event if context is canceled
	// during event read.
	tracererr := make(chan error, 1)
	go func() {
		tracererr <- tracer.Run(ctx)
	}()

	for _, namespace := range cfg.MutedNamespaces {
		err := ctrl.MuteNamespace(namespace)
		if err != nil {
			log.Warnf("error while muting namespace: %v", err)
		}
	}

	if err := containersClient.LoadContainers(ctx); err != nil {
		return fmt.Errorf("load containers: %w", err)
	}
	go containersRefreshLoop(ctx, cfg.ContainersRefreshInterval, log, containersClient)
	go containersMetrics(ctx, containersClient)

	log.Infof("running kvisor agent, version=%s, kernel_version=%s, init_duration=%v", cfg.Version, kernelVersion, time.Since(start))
	defer log.Infof("stopping kvisor agent, version=%s", cfg.Version)

	select {
	case err := <-tracererr:
		return err
	case <-ctx.Done():
		return waitWithTimeout(errg, 10*time.Second)
	}
}

func containersMetrics(ctx context.Context, client *containers.Client) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
			conts := client.ListContainers(func(c *containers.Container) bool {
				return true
			})
			metrics.AgentContainersCount.Set(float64(len(conts)))
		}
	}
}

func containersRefreshLoop(ctx context.Context, interval time.Duration, log *logging.Logger, client *containers.Client) {
	if interval == 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			func() {
				start := time.Now()
				if err := client.LoadContainers(ctx); err != nil {
					log.Warnf("refreshing containers, duration=%v: %v", err, time.Since(start))
				} else {
					log.Infof("refreshed containers, duration=%v", time.Since(start))
				}
			}()
		case <-ctx.Done():
			return
		}
	}
}

func enableBPFStats(cfg *config.Config, log *logging.Logger) func() {
	cleanup, err := ebpftracer.EnabledBPFStats(log)
	if err != nil {
		// In case we cannot enable bpf stats, there is no need to have the metrics export for them enabled.
		cfg.EBPFMetrics.ProgramMetricsEnabled = false
		return func() {}
	}

	return cleanup
}

func buildEBPFPolicy(log *logging.Logger, cfg *config.Config, signatureEngine *signature.SignatureEngine) *ebpftracer.Policy {
	// TODO: Allow to build these policies on the fly from the control plane. Ideally we should be able to disable, enable policies and change rate limits dynamically.
	policy := &ebpftracer.Policy{
		SystemEvents: []events.ID{
			events.CgroupMkdir,
			events.CgroupRmdir,
		},
		Events: []*ebpftracer.EventPolicy{},
	}

	dnsEventPolicy := &ebpftracer.EventPolicy{
		ID:                 events.NetPacketDNSBase,
		PreFilterGenerator: ebpftracer.DeduplicateDNSEventsPreFilter(log, 100, 60*time.Second),
		KernelFilters: []ebpftracer.KernelEventFilter{
			{
				Name: "Skip emtpy dns answers",
				Description: `Helper net_l7_empty_dns_answer is used to check if dns header answers field is non zero.
Currently we care only care about dns responses with valid answers.
`,
			},
		},
	}

	if cfg.ProcessTree.Enabled {
		policy.SystemEvents = append(policy.SystemEvents, []events.ID{
			events.SchedProcessExec,
			events.SchedProcessExit,
			events.SchedProcessFork,
		}...)
	}

	if cfg.Events.Enabled {
		policy.SignatureEvents = signatureEngine.TargetEvents()

		for _, enabledEvent := range cfg.EBPFEventsPolicyConfig.EnabledEvents {
			switch enabledEvent {
			case events.SockSetState:
				policy.Events = append(policy.Events, &ebpftracer.EventPolicy{
					ID: events.SockSetState,
				})
			case events.NetPacketDNSBase:
				policy.Events = append(policy.Events, dnsEventPolicy)
			default:
				policy.Events = append(policy.Events, &ebpftracer.EventPolicy{ID: enabledEvent})
			}
		}
	}

	if cfg.Netflow.Enabled {
		policy.Events = append(policy.Events, &ebpftracer.EventPolicy{
			ID: events.NetFlowBase,
		})
		// If ebpf events exporters are not enabled but flows collection enabled
		// we still may need dns events to enrich dns question.
		dnsEnabled := lo.ContainsBy(cfg.EBPFEventsPolicyConfig.EnabledEvents, func(item events.ID) bool {
			return item == events.NetPacketDNSBase
		})
		if !cfg.Events.Enabled && dnsEnabled {
			policy.Events = append(policy.Events, dnsEventPolicy)
		}
	}
	return policy
}

func (a *App) syncRemoteConfig(ctx context.Context, client *castai.Client) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		jsonConfig, err := json.Marshal(a.cfg) //nolint:musttag
		if err != nil {
			return fmt.Errorf("marshaling config: %w", err)
		}
		_, err = client.GRPC.GetConfiguration(ctx, &castaipb.GetConfigurationRequest{
			CurrentConfig: &castaipb.GetConfigurationRequest_Agent{
				Agent: jsonConfig,
			},
		})
		if err != nil {
			slog.Error(fmt.Sprintf("fetching initial config: %v", err))
			time.Sleep(5 * time.Second)
			continue
		}
		slog.Info("initial config synced")
		return nil
	}
}

func getActiveEnrichers(cfg config.EnricherConfig, log *logging.Logger, mountNamespacePIDStore *types.PIDsPerNamespace) []enrichment.EventEnricher {
	var result []enrichment.EventEnricher

	if cfg.EnableFileHashEnricher {
		result = append(result, enrichment.EnrichWithFileHash(log, mountNamespacePIDStore, proc.GetFS()))
	}
	if cfg.RedactSensitiveValuesRegex != nil {
		result = append(result, enrichment.NewSensitiveValueRedactor(cfg.RedactSensitiveValuesRegex))
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
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}

	go func() {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Error(err.Error())
		}
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
		return errors.New("timeout waiting for shutdown") // TODO(anjmao): Getting this error on tilt.
	case err := <-errc:
		return err
	}
}
