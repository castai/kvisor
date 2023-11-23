package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"strconv"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/bombsimon/logrusr/v4"
	"github.com/castai/kvisor/jobsgc"
	"github.com/cenkalti/backoff/v4"
	"github.com/containerd/containerd/pkg/atomic"
	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/castai/kvisor/blobscache"
	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/castai/telemetry"
	"github.com/castai/kvisor/cloudscan/eks"
	"github.com/castai/kvisor/cloudscan/gke"
	"github.com/castai/kvisor/config"
	"github.com/castai/kvisor/delta"
	"github.com/castai/kvisor/imagescan"
	"github.com/castai/kvisor/kube"
	"github.com/castai/kvisor/linters/kubebench"
	"github.com/castai/kvisor/linters/kubelinter"
	agentlog "github.com/castai/kvisor/log"
	"github.com/castai/kvisor/policy"
	"github.com/castai/kvisor/version"
)

// These should be set via `go build` during a release.
var (
	GitCommit = "undefined"
	GitRef    = "no-ref"
	Version   = "local"
)

var (
	configPath = flag.String("config", "/etc/castai/config/config.yaml", "Config file path")
)

func main() {
	flag.Parse()

	logger := logrus.New()
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal(err)
	}
	lvl, _ := logrus.ParseLevel(cfg.Log.Level)
	logger.SetLevel(lvl)

	binVersion := config.SecurityAgentVersion{
		GitCommit: GitCommit,
		GitRef:    GitRef,
		Version:   Version,
	}

	client := castai.NewClient(
		cfg.API.URL, cfg.API.Key,
		logger,
		cfg.API.ClusterID,
		cfg.PolicyEnforcement.Enabled,
		"castai-kvisor",
		binVersion,
	)

	log := logrus.WithFields(logrus.Fields{})
	e := agentlog.NewExporter(logger, client, []logrus.Level{
		logrus.ErrorLevel,
		logrus.FatalLevel,
		logrus.PanicLevel,
		logrus.InfoLevel,
		logrus.WarnLevel,
	})

	logger.AddHook(e)
	logrus.RegisterExitHandler(e.Wait)

	ctx := signals.SetupSignalHandler()
	if err := run(ctx, logger, client, cfg, binVersion); err != nil && !errors.Is(err, context.Canceled) {
		logErr := &logContextErr{}
		if errors.As(err, &logErr) {
			log = logger.WithFields(logErr.fields)
		}
		log.Fatalf("castai-kvisor failed: %v", err)
	}
	log.Info("castai-kvisor stopped")
}

func run(ctx context.Context, logger logrus.FieldLogger, castaiClient castai.Client, cfg config.Config, binVersion config.SecurityAgentVersion) (reterr error) {
	fields := logrus.Fields{}

	defer func() {
		if reterr == nil {
			return
		}
		reterr = &logContextErr{
			err:    reterr,
			fields: fields,
		}
	}()

	kubeConfig, err := retrieveKubeConfig(logger, cfg.KubeClient.KubeConfigPath)
	if err != nil {
		return err
	}

	kubeConfig.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(float32(cfg.KubeClient.QPS), cfg.KubeClient.Burst)
	if cfg.KubeClient.UseProtobuf {
		kubeConfig.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
		kubeConfig.ContentType = "application/vnd.kubernetes.protobuf"
	}

	clientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	k8sVersion, err := version.Get(clientSet)
	if err != nil {
		return fmt.Errorf("getting kubernetes version: %w", err)
	}

	log := logger.WithFields(logrus.Fields{
		"version":     binVersion.Version,
		"k8s_version": k8sVersion.Full,
	})

	log.Infof("running castai-kvisor version %v", binVersion)

	snapshotProvider := delta.NewSnapshotProvider()

	informersFactory := informers.NewSharedInformerFactory(clientSet, 0)
	kubeCtrl := kube.NewController(log, informersFactory, k8sVersion)

	deltaCtrl := delta.NewController(
		log,
		log.Level,
		delta.Config{DeltaSyncInterval: cfg.DeltaSyncInterval},
		castaiClient,
		snapshotProvider,
		k8sVersion.MinorInt,
		kubeCtrl,
	)
	kubeCtrl.AddSubscribers(deltaCtrl)

	telemetryManager := telemetry.NewManager(log, castaiClient, cfg.Telemetry.Interval)

	var scannedNodes []string
	telemetryResponse, err := castaiClient.PostTelemetry(ctx, true)
	if err != nil {
		log.Warnf("initial telemetry: %v", err)
	} else {
		cfg = telemetry.ModifyConfig(cfg, telemetryResponse)
		scannedNodes = telemetryResponse.NodeIDs
	}

	linter, err := kubelinter.New(lo.Keys(castai.LinterRuleMap))
	if err != nil {
		return fmt.Errorf("setting up linter: %w", err)
	}

	if cfg.Linter.Enabled {
		log.Info("linter enabled")
		linterCtrl := kubelinter.NewController(log, cfg.Linter, castaiClient, linter)
		kubeCtrl.AddSubscribers(linterCtrl)
	}
	if cfg.KubeBench.Enabled {
		log.Info("kubebench enabled")
		if cfg.KubeBench.Force {
			scannedNodes = []string{}
		}
		podLogReader := agentlog.NewPodLogReader(clientSet)
		kubeBenchCtrl := kubebench.NewController(
			log,
			clientSet,
			cfg.PodNamespace,
			cfg.Provider,
			cfg.KubeBench.ScanInterval,
			castaiClient,
			podLogReader,
			scannedNodes,
		)
		kubeCtrl.AddSubscribers(kubeBenchCtrl)
	}
	var imgScanCtrl *imagescan.Controller
	if cfg.ImageScan.Enabled {
		log.Info("imagescan enabled")
		imgScanCtrl = imagescan.NewController(
			log,
			cfg.ImageScan,
			imagescan.NewImageScanner(clientSet, cfg),
			castaiClient,
			k8sVersion.MinorInt,
			kubeCtrl,
		)
		kubeCtrl.AddSubscribers(imgScanCtrl)
	}

	if cfg.CloudScan.Enabled {
		switch cfg.Provider {
		case "gke":
			gkeCloudScanner, err := gke.NewScanner(log, cfg.CloudScan, cfg.ImageScan.Enabled, castaiClient)
			if err != nil {
				return err
			}
			go gkeCloudScanner.Start(ctx)
		case "eks":
			awscfg, err := awsconfig.LoadDefaultConfig(ctx)
			if err != nil {
				return err
			}

			go eks.NewScanner(log, cfg.CloudScan, awseks.NewFromConfig(awscfg), castaiClient).Start(ctx)
		}
	}

	resyncObserver := delta.ResyncObserver(ctx, log, snapshotProvider, castaiClient)
	telemetryManager.AddObservers(resyncObserver)
	featureObserver, featuresCtx := telemetry.ObserveDisabledFeatures(ctx, cfg, log)
	telemetryManager.AddObservers(featureObserver)

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)

	logr := logrusr.New(logger)
	klog.SetLogger(logr)

	mngr, err := manager.New(kubeConfig, manager.Options{
		Logger:                  logr.WithName("manager"),
		Port:                    cfg.ServicePort,
		CertDir:                 cfg.CertsDir,
		NewCache:                cache.New,
		Scheme:                  scheme,
		MetricsBindAddress:      "0",
		HealthProbeBindAddress:  ":" + strconv.Itoa(cfg.StatusPort),
		LeaderElection:          cfg.LeaderElection,
		LeaderElectionID:        cfg.ServiceName,
		LeaderElectionNamespace: cfg.PodNamespace,
		MapperProvider: func(c *rest.Config) (meta.RESTMapper, error) {
			return apiutil.NewDynamicRESTMapper(c)
		},
	})
	if err != nil {
		return fmt.Errorf("setting up manager: %w", err)
	}

	if err := mngr.AddHealthzCheck("default", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz check: %w", err)
	}

	if err := mngr.AddReadyzCheck("default", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz check: %w", err)
	}

	if cfg.PolicyEnforcement.Enabled {
		policyEnforcer := policy.NewEnforcer(linter, cfg.PolicyEnforcement)
		telemetryManager.AddObservers(policyEnforcer.TelemetryObserver())

		rotatorReady := make(chan struct{})
		err = rotator.AddRotator(mngr, &rotator.CertRotator{
			SecretKey: types.NamespacedName{
				Name:      cfg.CertsSecret,
				Namespace: cfg.PodNamespace,
			},
			CertDir:        cfg.CertsDir,
			CAName:         "kvisor",
			CAOrganization: "cast.ai",
			DNSName:        fmt.Sprintf("%s.%s.svc", cfg.ServiceName, cfg.PodNamespace),
			IsReady:        rotatorReady,
			Webhooks: []rotator.WebhookInfo{
				{
					Name: cfg.PolicyEnforcement.WebhookName,
					Type: rotator.Validating,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("setting up cert rotation: %w", err)
		}

		ready := atomic.NewBool(false)
		if err := mngr.AddReadyzCheck("webhook", func(req *http.Request) error {
			if !ready.IsSet() {
				return errors.New("webhook is not ready yet")
			}
			return nil
		}); err != nil {
			return fmt.Errorf("add readiness check: %w", err)
		}

		go func() {
			<-rotatorReady
			mngr.GetWebhookServer().Register("/validate", &admission.Webhook{
				Handler: policyEnforcer,
			})
			ready.Set()
		}()
	}

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/debug/pprof/", pprof.Index)
	httpMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	httpMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	httpMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	httpMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	httpMux.Handle("/metrics", promhttp.Handler())
	if cfg.ImageScan.Enabled {
		scanHandler := imagescan.NewHttpHandlers(log, castaiClient, imgScanCtrl)
		httpMux.HandleFunc("/v1/image-scan/report", scanHandler.HandleImageMetadata)
		httpMux.HandleFunc("/debug/images", scanHandler.HandleDebugGetImages)
		httpMux.HandleFunc("/debug/images/details", scanHandler.HandleDebugGetImage)
		blobsCache := blobscache.NewServer(log, blobscache.ServerConfig{})
		blobsCache.RegisterHandlers(httpMux)
	}

	if err := mngr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		// Start http server for scan job, metrics and pprof handlers.
		httpAddr := fmt.Sprintf(":%d", cfg.HTTPPort)
		log.Infof("starting http server on %s", httpAddr)

		srv := &http.Server{
			Addr:         httpAddr,
			Handler:      httpMux,
			WriteTimeout: 5 * time.Second,
			ReadTimeout:  5 * time.Second,
		}
		return srv.ListenAndServe()
	})); err != nil {
		return fmt.Errorf("add http server: %w", err)
	}

	if err := mngr.Add(telemetryManager); err != nil {
		return fmt.Errorf("add telemetry manager: %w", err)
	}

	gc := jobsgc.NewGC(log, clientSet, jobsgc.Config{
		CleanupInterval: 10 * time.Minute,
		CleanupJobAge:   10 * time.Minute,
		Namespace:       cfg.PodNamespace,
	})

	if err := mngr.Add(gc); err != nil {
		return fmt.Errorf("add jobs gc: %w", err)
	}

	if err := mngr.Add(kubeCtrl); err != nil {
		return fmt.Errorf("add kube controller: %w", err)
	}

	return mngr.Start(featuresCtx)
}

func retrieveKubeConfig(log logrus.FieldLogger, kubepath string) (*rest.Config, error) {
	if kubepath != "" {
		data, err := os.ReadFile(kubepath)
		if err != nil {
			return nil, fmt.Errorf("reading kubeconfig at %s: %w", kubepath, err)
		}
		restConfig, err := clientcmd.RESTConfigFromKubeConfig(data)
		if err != nil {
			return nil, fmt.Errorf("building rest config from kubeconfig at %s: %w", kubepath, err)
		}
		log.Debug("using kubeconfig from env variables")
		return restConfig, nil
	}

	inClusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	inClusterConfig.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return &kubeRetryTransport{
			log:           log,
			next:          rt,
			maxRetries:    10,
			retryInterval: 3 * time.Second,
		}
	})
	log.Debug("using in cluster kubeconfig")
	return inClusterConfig, nil
}

type kubeRetryTransport struct {
	log           logrus.FieldLogger
	next          http.RoundTripper
	maxRetries    uint64
	retryInterval time.Duration
}

func (rt *kubeRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	err := backoff.RetryNotify(func() error {
		var err error
		resp, err = rt.next.RoundTrip(req) //nolint:bodyclose
		if err != nil {
			// Previously client-go contained logic to retry connection refused errors. See https://github.com/kubernetes/kubernetes/pull/88267/files
			if net.IsConnectionRefused(err) {
				return err
			}
			return backoff.Permanent(err)
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(rt.retryInterval), rt.maxRetries),
		func(err error, duration time.Duration) {
			if err != nil {
				rt.log.Warnf("kube api server connection refused, will retry: %v", err)
			}
		})
	return resp, err
}

type logContextErr struct {
	err    error
	fields logrus.Fields
}

func (e *logContextErr) Error() string {
	return e.err.Error()
}

func (e *logContextErr) Unwrap() error {
	return e.err
}
