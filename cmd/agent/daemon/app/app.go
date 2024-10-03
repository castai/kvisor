package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"regexp"
	"runtime"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	kubepb "github.com/castai/kvisor/api/v1/kube"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/conntrack"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/cmd/agent/daemon/netstats"
	"github.com/castai/kvisor/cmd/agent/daemon/state"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/go-playground/validator/v10"
	"github.com/grafana/pyroscope-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type EBPFMetricsConfig struct {
	TracerMetricsEnabled  bool `json:"TracerMetricsEnabled"`
	ProgramMetricsEnabled bool `json:"ProgramMetricsEnabled"`
}

type Config struct {
	LogLevel                       string                          `json:"logLevel"`
	LogRateInterval                time.Duration                   `json:"logRateInterval"`
	LogRateBurst                   int                             `json:"logRateBurst"`
	SendLogsLevel                  string                          `json:"sendLogsLevel"`
	Version                        string                          `json:"version"`
	BTFPath                        string                          `json:"BTFPath"`
	PyroscopeAddr                  string                          `json:"pyroscopeAddr"`
	ContainerdSockPath             string                          `json:"containerdSockPath"`
	HostCgroupsDir                 string                          `json:"hostCgroupsDir"`
	MetricsHTTPListenPort          int                             `json:"metricsHTTPListenPort"`
	State                          state.Config                    `json:"state"`
	ContainerStatsEnabled          bool                            `json:"containerStatsEnabled"`
	EBPFEventsEnabled              bool                            `json:"EBPFEventsEnabled"`
	EBPFEventsPerCPUBuffer         int                             `validate:"required" json:"EBPFEventsPerCPUBuffer"`
	EBPFEventsOutputChanSize       int                             `validate:"required" json:"EBPFEventsOutputChanSize"`
	EBPFEventsStdioExporterEnabled bool                            `json:"EBPFEventsStdioExporterEnabled"`
	EBPFMetrics                    EBPFMetricsConfig               `json:"EBPFMetrics"`
	EBPFEventsPolicyConfig         ebpftracer.EventsPolicyConfig   `json:"EBPFEventsPolicyConfig"`
	MutedNamespaces                []string                        `json:"mutedNamespaces"`
	SignatureEngineConfig          signature.SignatureEngineConfig `json:"signatureEngineConfig"`
	Castai                         castai.Config                   `json:"castai"`
	EnricherConfig                 EnricherConfig                  `json:"enricherConfig"`
	Netflow                        NetflowConfig                   `json:"netflow"`
	ProcessTree                    ProcessTreeConfig               `json:"processTree"`
	Clickhouse                     ClickhouseConfig                `json:"clickhouse"`
	KubeAPIServiceAddr             string                          `json:"kubeAPIServiceAddr"`
	ExportersQueueSize             int                             `validate:"required" json:"exportersQueueSize"`
}

type EnricherConfig struct {
	EnableFileHashEnricher     bool           `json:"enableFileHashEnricher"`
	RedactSensitiveValuesRegex *regexp.Regexp `json:"redactSensitiveValuesRegex"`
}

type NetflowConfig struct {
	Enabled                     bool                       `json:"enabled"`
	SampleSubmitIntervalSeconds uint64                     `json:"sampleSubmitIntervalSeconds"`
	OutputChanSize              int                        `json:"outputChanSize"`
	Grouping                    ebpftracer.NetflowGrouping `json:"grouping"`
}

type ClickhouseConfig struct {
	Addr     string `json:"addr"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ProcessTreeConfig struct {
	Enabled bool `json:"enabled"`
}

func New(cfg *Config) *App {
	if err := validator.New().Struct(cfg); err != nil {
		panic(fmt.Errorf("invalid config: %w", err).Error())
	}
	return &App{cfg: cfg}
}

type App struct {
	cfg *Config
}

func (a *App) Run(ctx context.Context) error {
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
	var log *logging.Logger
	var exporters *state.Exporters
	// Castai specific spetup if config is valid.
	if cfg.Castai.Valid() {
		castaiClient, err := castai.NewClient(fmt.Sprintf("kvisor-agent/%s", cfg.Version), cfg.Castai)
		if err != nil {
			return fmt.Errorf("setting up castai api client: %w", err)
		}
		if err := a.syncRemoteConfig(ctx, castaiClient); err != nil {
			return fmt.Errorf("sync remote config: %w", err)
		}
		if a.cfg.SendLogsLevel != "" && a.cfg.Castai.Valid() {
			castaiLogsExporter := castai.NewLogsExporter(castaiClient)
			go castaiLogsExporter.Run(ctx) //nolint:errcheck

			logCfg.Export = logging.ExportConfig{
				ExportFunc: castaiLogsExporter.ExportFunc(),
				MinLevel:   logging.MustParseLevel(a.cfg.SendLogsLevel),
			}
			log = logging.New(logCfg)
		}
		exporters = state.NewExporters(log)
		if cfg.EBPFEventsEnabled {
			exporters.Events = append(exporters.Events, state.NewCastaiEventsExporter(log, castaiClient, a.cfg.ExportersQueueSize))
		}
		if cfg.ContainerStatsEnabled {
			exporters.ContainerStats = append(exporters.ContainerStats, state.NewCastaiContainerStatsExporter(log, castaiClient, a.cfg.ExportersQueueSize))
		}
		if cfg.Netflow.Enabled {
			exporters.Netflow = append(exporters.Netflow, state.NewCastaiNetflowExporter(log, castaiClient, a.cfg.ExportersQueueSize))
		}
		if cfg.ProcessTree.Enabled {
			exporter := state.NewCastaiProcessTreeExporter(log, castaiClient, a.cfg.ExportersQueueSize)
			exporters.ProcessTree = append(exporters.ProcessTree, exporter)
		}
	} else {
		log = logging.New(logCfg)
		exporters = state.NewExporters(log)
	}

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

		if cfg.Netflow.Enabled {
			clickhouseNetflowExporter := state.NewClickhouseNetflowExporter(log, storageConn, a.cfg.ExportersQueueSize)
			exporters.Netflow = append(exporters.Netflow, clickhouseNetflowExporter)
		}

		if cfg.ProcessTree.Enabled {
			exporter := state.NewClickhouseProcessTreeExporter(log, storageConn, a.cfg.ExportersQueueSize)
			exporters.ProcessTree = append(exporters.ProcessTree, exporter)
		}
	}

	if cfg.EBPFEventsStdioExporterEnabled {
		exporters.Events = append(exporters.Events, state.NewStdioEventsExporter(log))
	}

	if exporters.Empty() {
		return errors.New("no configured exporters")
	}

	log.Infof("running kvisor agent, version=%s", a.cfg.Version)
	defer log.Infof("stopping kvisor agent, version=%s", a.cfg.Version)

	if addr := a.cfg.PyroscopeAddr; addr != "" {
		withPyroscope(addr)
	}

	cgroupClient, err := cgroup.NewClient(log, a.cfg.HostCgroupsDir)
	if err != nil {
		return err
	}
	procHandler := proc.New()
	containersClient, err := containers.NewClient(log, cgroupClient, a.cfg.ContainerdSockPath, procHandler)
	if err != nil {
		return err
	}

	var processTreeCollector processtree.ProcessTreeCollector
	if cfg.ProcessTree.Enabled {
		processTreeCollector, err = initializeProcessTree(ctx, log, procHandler, containersClient)
		if err != nil {
			return fmt.Errorf("initialize process tree: %w", err)
		}
	} else {
		processTreeCollector = processtree.NewNoop()
	}

	ct, err := conntrack.NewClient(log)
	if err != nil {
		return fmt.Errorf("conntrack: %w", err)
	}
	defer ct.Close()

	activeSignatures, err := signature.DefaultSignatures(log, a.cfg.SignatureEngineConfig)
	if err != nil {
		return fmt.Errorf("error while configuring signatures: %w", err)
	}
	signatureEngine := signature.NewEngine(activeSignatures, log, a.cfg.SignatureEngineConfig)

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

	if cfg.EBPFMetrics.ProgramMetricsEnabled {
		cleanup := enableBPFStats(cfg, log)
		defer cleanup()
	}

	tracer := ebpftracer.New(log, ebpftracer.Config{
		BTFPath:                            a.cfg.BTFPath,
		EventsPerCPUBuffer:                 a.cfg.EBPFEventsPerCPUBuffer,
		EventsOutputChanSize:               a.cfg.EBPFEventsOutputChanSize,
		DefaultCgroupsVersion:              cgroupClient.DefaultCgroupVersion().String(),
		ContainerClient:                    containersClient,
		CgroupClient:                       cgroupClient,
		SignatureEngine:                    signatureEngine,
		MountNamespacePIDStore:             mountNamespacePIDStore,
		HomePIDNS:                          pidNSID,
		NetflowOutputChanSize:              a.cfg.Netflow.OutputChanSize,
		NetflowSampleSubmitIntervalSeconds: a.cfg.Netflow.SampleSubmitIntervalSeconds,
		NetflowGrouping:                    a.cfg.Netflow.Grouping,
		TrackSyscallStats:                  cfg.ContainerStatsEnabled,
		ProcessTreeCollector:               processTreeCollector,
		MetricsReporting: ebpftracer.MetricsReportingConfig{
			ProgramMetricsEnabled: cfg.EBPFMetrics.ProgramMetricsEnabled,
			TracerMetricsEnabled:  cfg.EBPFMetrics.TracerMetricsEnabled,
		},
	})
	if err := tracer.Load(); err != nil {
		return fmt.Errorf("loading tracer: %w", err)
	}
	defer tracer.Close()

	policy := buildEBPFPolicy(log, cfg, exporters, signatureEngine)
	// TODO: Allow to change policy on the fly. We should be able to change it from remote config.
	if err := tracer.ApplyPolicy(policy); err != nil {
		return fmt.Errorf("apply policy: %w", err)
	}

	netStatsReader := netstats.NewReader(proc.Path)

	ctrl := state.NewController(
		log,
		a.cfg.State,
		exporters,
		containersClient,
		netStatsReader,
		ct,
		tracer,
		signatureEngine,
		enrichmentService,
		kubeAPIServerClient,
		processTreeCollector,
	)

	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		return a.runHTTPServer(ctx, log)
	})

	errg.Go(func() error {
		return exporters.Run(ctx)
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

	for _, namespace := range a.cfg.MutedNamespaces {
		err := ctrl.MuteNamespace(namespace)
		if err != nil {
			log.Warnf("error while muting namespace: %v", err)
		}
	}

	select {
	case err := <-tracererr:
		return err
	case <-ctx.Done():
		return waitWithTimeout(errg, 10*time.Second)
	}
}

func enableBPFStats(cfg *Config, log *logging.Logger) func() {
	cleanup, err := ebpftracer.EnabledBPFStats(log)
	if err != nil {
		// In case we cannot enable bpf stats, there is no need to have the metrics export for them enabled.
		cfg.EBPFMetrics.ProgramMetricsEnabled = false
		return func() {}
	}

	return cleanup
}

func buildEBPFPolicy(log *logging.Logger, cfg *Config, exporters *state.Exporters, signatureEngine *signature.SignatureEngine) *ebpftracer.Policy {
	policy := &ebpftracer.Policy{
		SystemEvents: []events.ID{
			events.CgroupMkdir,
			events.CgroupRmdir,
		},
		Events: []*ebpftracer.EventPolicy{},
	}

	dnsEventPolicy := &ebpftracer.EventPolicy{
		ID: events.NetPacketDNSBase,
		FilterGenerator: ebpftracer.FilterAnd(
			ebpftracer.FilterEmptyDnsAnswers(log),
			ebpftracer.DeduplicateDnsEvents(log, 100, 60*time.Second),
		),
	}

	if cfg.ProcessTree.Enabled {
		policy.SystemEvents = append(policy.SystemEvents, []events.ID{
			events.SchedProcessExec,
			events.SchedProcessExit,
			events.SchedProcessFork,
		}...)
	}

	if len(exporters.Events) > 0 {
		policy.SignatureEvents = signatureEngine.TargetEvents()

		for _, enabledEvent := range cfg.EBPFEventsPolicyConfig.EnabledEvents {
			switch enabledEvent {
			case events.SockSetState:
				policy.Events = append(policy.Events, &ebpftracer.EventPolicy{
					ID: events.SockSetState,
					FilterGenerator: ebpftracer.RateLimitPrivateIP(ebpftracer.RateLimitPolicy{
						Rate:  100,
						Burst: 1,
					}),
				})
			case events.NetPacketDNSBase:
				policy.Events = append(policy.Events, dnsEventPolicy)
			default:
				policy.Events = append(policy.Events, &ebpftracer.EventPolicy{ID: enabledEvent})
			}
		}
	}

	if len(exporters.Netflow) > 0 {
		policy.Events = append(policy.Events, &ebpftracer.EventPolicy{
			ID: events.NetFlowBase,
		})
		// If ebpf events exporters are not enabled but flows collection enabled
		// we still may need dns events to enrich dns question.
		dnsEnabled := lo.ContainsBy(cfg.EBPFEventsPolicyConfig.EnabledEvents, func(item events.ID) bool {
			return item == events.NetPacketDNSBase
		})
		if len(exporters.Events) == 0 && dnsEnabled {
			policy.Events = append(policy.Events, dnsEventPolicy)
		}
	}
	return policy
}

func initializeProcessTree(ctx context.Context, log *logging.Logger, procHandler *proc.Proc, containersClient *containers.Client) (*processtree.ProcessTreeCollectorImpl, error) {
	processTreeCollector, err := processtree.New(log, procHandler, containersClient)
	if err != nil {
		return nil, err
	}
	err = processTreeCollector.Init(ctx)
	if err != nil {
		return nil, err
	}
	return processTreeCollector, nil
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

func getActiveEnrichers(cfg EnricherConfig, log *logging.Logger, mountNamespacePIDStore *types.PIDsPerNamespace) []enrichment.EventEnricher {
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
		return errors.New("timeout waiting for shutdown") // TODO(anjmao): Getting this error on tilt.
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
