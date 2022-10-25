package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	"k8s.io/client-go/informers"

	"github.com/castai/sec-agent/blobscache"
	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/castai/telemetry"
	"github.com/castai/sec-agent/cloudscan/eks"
	"github.com/castai/sec-agent/cloudscan/gke"
	"github.com/castai/sec-agent/config"
	"github.com/castai/sec-agent/controller"
	"github.com/castai/sec-agent/delta"
	"github.com/castai/sec-agent/imagescan"
	"github.com/castai/sec-agent/imagescan/allow"
	"github.com/castai/sec-agent/jobsgc"
	"github.com/castai/sec-agent/linters/kubebench"
	"github.com/castai/sec-agent/linters/kubelinter"
	agentlog "github.com/castai/sec-agent/log"
	"github.com/castai/sec-agent/version"

	"github.com/cenkalti/backoff/v4"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

// These should be set via `go build` during a release.
var (
	GitCommit = "undefined"
	GitRef    = "no-ref"
	Version   = "local"
)

func main() {
	logger := logrus.New()
	cfg, err := config.Load("/etc/castai/config/config.yaml")
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
		"castai-sec-agent",
		binVersion,
	)

	log := logrus.WithFields(logrus.Fields{})
	e := agentlog.NewExporter(logger, client)
	logger.AddHook(e)
	logrus.RegisterExitHandler(e.Wait)

	ctx := signals.SetupSignalHandler()
	if err := run(ctx, logger, client, cfg, binVersion); err != nil {
		logErr := &logContextErr{}
		if errors.As(err, &logErr) {
			log = logger.WithFields(logErr.fields)
		}
		log.Fatalf("castai-sec-agent failed: %v", err)
	}
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

	restconfig, err := retrieveKubeConfig(logger, cfg.KubeClient.KubeConfigPath)
	if err != nil {
		return err
	}

	restconfig.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(float32(cfg.KubeClient.QPS), cfg.KubeClient.Burst)

	clientset, err := kubernetes.NewForConfig(restconfig)
	if err != nil {
		return err
	}

	k8sVersion, err := version.Get(clientset)
	if err != nil {
		return fmt.Errorf("getting kubernetes version: %w", err)
	}

	log := logger.WithFields(logrus.Fields{
		"version":     binVersion.Version,
		"k8s_version": k8sVersion.Full,
	})

	httpMux := http.NewServeMux()
	healthz.InstallHandler(httpMux)
	installPprofHandlers(httpMux)

	// Start http server for pprof and health checks handlers.
	go func() {
		addr := fmt.Sprintf(":%d", cfg.PprofPort)
		log.Infof("starting pprof server on %s", addr)

		if err := http.ListenAndServe(addr, httpMux); err != nil {
			log.Errorf("failed to start pprof http server: %v", err)
		}
	}()

	log.Infof("running castai-sec-agent version %v", binVersion)

	snapshotProvider := delta.NewSnapshotProvider()

	objectSubscribers := []controller.ObjectSubscriber{
		delta.NewSubscriber(
			log,
			log.Level,
			delta.Config{DeltaSyncInterval: cfg.DeltaSyncInterval},
			castaiClient,
			snapshotProvider,
			k8sVersion.MinorInt,
		),
	}

	telemetryResponse, err := castaiClient.PostTelemetry(ctx)
	if err != nil {
		log.Warnf("initial telemetry: %v", err)
	} else {
		cfg = telemetry.ModifyConfig(cfg, telemetryResponse)
	}

	if cfg.Linter.Enabled {
		log.Info("linter enabled")
		linterSub, err := kubelinter.NewSubscriber(log, castaiClient)
		if err != nil {
			return err
		}
		objectSubscribers = append(objectSubscribers, linterSub)
	}
	if cfg.KubeBench.Enabled {
		log.Info("kubebench enabled")
		podLogReader := agentlog.NewPodLogReader(clientset)
		objectSubscribers = append(objectSubscribers, kubebench.NewSubscriber(log, clientset, cfg.PodNamespace, cfg.Provider, castaiClient, podLogReader))
	}
	if cfg.ImageScan.Enabled {
		log.Info("imagescan enabled")
		allowSubscriber := allow.NewSubscriber()
		objectSubscribers = append(objectSubscribers, allowSubscriber)
		objectSubscribers = append(objectSubscribers, imagescan.NewSubscriber(
			log,
			cfg.ImageScan,
			castaiClient,
			imagescan.NewImageScanner(clientset, cfg),
			k8sVersion.MinorInt,
			allowSubscriber.FindBestNode,
		))
		blobsCache := blobscache.NewBlobsCacheServer(log, blobscache.ServerConfig{ServePort: cfg.ImageScan.BlobsCachePort})
		go blobsCache.Start(ctx)
	}
	if len(objectSubscribers) == 0 {
		return errors.New("no subscribers enabled")
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

	gc := jobsgc.NewGC(log, clientset, jobsgc.Config{
		CleanupInterval: 10 * time.Minute,
		CleanupJobAge:   10 * time.Minute,
	})
	go gc.Start(ctx)

	informersFactory := informers.NewSharedInformerFactory(clientset, 0)
	ctrl := controller.New(log, informersFactory, objectSubscribers, k8sVersion)

	telemetryManager := telemetry.NewManager(ctx, log, castaiClient)
	resyncObserver := delta.ResyncObserver(ctx, log, snapshotProvider, castaiClient)
	featureObserver, featuresCtx := telemetry.ObserveDisabledFeatures(ctx, cfg, log)

	go telemetryManager.Observe(resyncObserver, featureObserver)

	// Does the work. Blocks.
	return ctrl.Run(featuresCtx)
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

func installPprofHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
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
		resp, err = rt.next.RoundTrip(req)
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
