package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"k8s.io/client-go/informers"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/config"
	"github.com/castai/sec-agent/controller"
	"github.com/castai/sec-agent/delta"
	"github.com/castai/sec-agent/imagescan"
	"github.com/castai/sec-agent/linters/kubebench"
	"github.com/castai/sec-agent/linters/kubelinter"
	agentlog "github.com/castai/sec-agent/log"
	"github.com/castai/sec-agent/version"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
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
	cfg := config.Get()

	binVersion := &config.SecurityAgentVersion{
		GitCommit: GitCommit,
		GitRef:    GitRef,
		Version:   Version,
	}

	logger := logrus.New()
	logger.SetLevel(logrus.Level(cfg.Log.Level))

	client := castai.NewClient(
		cfg.API.URL, cfg.API.Key,
		logger,
		cfg.ClusterID,
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

func run(ctx context.Context, logger logrus.FieldLogger, castaiClient castai.Client, cfg config.Config, binVersion *config.SecurityAgentVersion) (reterr error) {
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

	restconfig, err := retrieveKubeConfig(logger)
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
		"k8s_version": k8sVersion.Full(),
	})

	httpMux := http.NewServeMux()
	var checks []healthz.HealthChecker
	var leaderHealthCheck *leaderelection.HealthzAdaptor
	if cfg.LeaderElection.Enabled {
		leaderHealthCheck = leaderelection.NewLeaderHealthzAdaptor(time.Minute * 2)
		checks = append(checks, leaderHealthCheck)
	}

	healthz.InstallHandler(httpMux, checks...)
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

	objectSubscribers := []controller.ObjectSubscriber{
		delta.NewSubscriber(
			log,
			log.Level,
			delta.Config{DeltaSyncInterval: cfg.DeltaSyncInterval},
			castaiClient,
			k8sVersion.MinorInt(),
		),
	}
	if cfg.Features.KubeLinter.Enabled {
		log.Info("kubelinter enabled")
		objectSubscribers = append(objectSubscribers, kubelinter.NewSubscriber(log))
	}
	if cfg.Features.KubeBench.Enabled {
		log.Info("kubebench enabled")
		podLogReader := kubebench.NewPodLogReader(clientset)
		objectSubscribers = append(objectSubscribers, kubebench.NewSubscriber(log, clientset, cfg.Provider, castaiClient, podLogReader))
	}
	if cfg.Features.ImageScan.Enabled {
		log.Info("imagescan enabled")
		objectSubscribers = append(objectSubscribers, imagescan.NewSubscriber(log, imagescan.Config{
			ScanInterval:       cfg.Features.ImageScan.ScanInterval,
			MaxConcurrentScans: cfg.Features.ImageScan.MaxConcurrentScans,
		}, imagescan.NewImageScanner(clientset)))
	}

	if len(objectSubscribers) == 0 {
		log.Fatal("no subscribers enabled")
	}

	informersFactory := informers.NewSharedInformerFactory(clientset, 0)
	ctrl := controller.New(log, informersFactory, objectSubscribers, k8sVersion)

	work := func(ctx context.Context) {
		if err := ctrl.Run(ctx); err != nil {
			log.Errorf("running controller: %v", err)
			return
		}
	}

	if cfg.LeaderElection.Enabled {
		// Run actions service with leader election. Blocks.
		return runWithLeaderElection(ctx, log, cfg.LeaderElection, clientset, leaderHealthCheck, work)
	}

	// Does the work. Blocks.
	work(ctx)
	return nil
}

func runWithLeaderElection(
	ctx context.Context,
	log logrus.FieldLogger,
	cfg config.LeaderElection,
	clientset kubernetes.Interface,
	watchDog *leaderelection.HealthzAdaptor,
	runFunc func(ctx context.Context),
) error {
	id, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to determine hostname used in leader ID: %w", err)
	}
	id = id + "_" + uuid.New().String()

	// Start the leader election code loop
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{
				Name:      cfg.LockName,
				Namespace: cfg.Namespace,
			},
			Client: clientset.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{
				Identity: id,
			},
		},
		// IMPORTANT: you MUST ensure that any code you have that
		// is protected by the lease must terminate **before**
		// you call cancel. Otherwise, you could have a background
		// loop still running and another process could
		// get elected before your background loop finished, violating
		// the stated goal of the lease.
		ReleaseOnCancel: true,
		LeaseDuration:   60 * time.Second,
		RenewDeadline:   15 * time.Second,
		RetryPeriod:     5 * time.Second,
		WatchDog:        watchDog,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				log.Infof("started leader: %s", id)
				runFunc(ctx)
			},
			OnStoppedLeading: func() {
				log.Infof("leader lost: %s", id)
				os.Exit(0)
			},
			OnNewLeader: func(identity string) {
				// We're notified when new leader elected.
				if identity == id {
					// I just got the lock.
					return
				}
				log.Infof("new leader elected: %s", identity)
			},
		},
	})
	return nil
}

func retrieveKubeConfig(log logrus.FieldLogger) (*rest.Config, error) {
	kubeconfig, err := kubeConfigFromEnv()
	if err != nil {
		return nil, err
	}

	if kubeconfig != nil {
		log.Debug("using kubeconfig from env variables")
		return kubeconfig, nil
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

func kubeConfigFromEnv() (*rest.Config, error) {
	kubepath := config.Get().Kubeconfig
	if kubepath == "" {
		return nil, nil
	}

	data, err := ioutil.ReadFile(kubepath)
	if err != nil {
		return nil, fmt.Errorf("reading kubeconfig at %s: %w", kubepath, err)
	}

	restConfig, err := clientcmd.RESTConfigFromKubeConfig(data)
	if err != nil {
		return nil, fmt.Errorf("building rest config from kubeconfig at %s: %w", kubepath, err)
	}

	return restConfig, nil
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
