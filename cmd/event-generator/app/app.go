package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"
)

type Config struct {
	Version       string
	Log           *logging.Logger
	Kubeconfig    string
	ThiefDelay    time.Duration
	ThiefInterval time.Duration
}

func New(cfg *Config) (*App, error) {
	log := cfg.Log

	return &App{
		cfg:      cfg,
		nodeName: os.Getenv("NODE_NAME"),
		log:      log,
	}, nil
}

type App struct {
	cfg      *Config
	nodeName string
	log      *logging.Logger
}

func (a *App) Run(mode string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch mode {
	case "controller":
		log := a.log
		kubeConfig, err := getKubeConfig(log, a.cfg.Kubeconfig)
		if err != nil {
			log.Fatal(err.Error())
		}
		kubeConfig.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(float32(25), 100)
		clientset, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			return err
		}
		ctrl := newController(a.log, clientset)
		return ctrl.run(ctx)
	case "thief":
		t := newThief(a.log, a.cfg)
		return t.run(ctx)
	default:
		runner := newEventRunner(a.log)
		if err := runner.run(ctx); err != nil {
			a.log.Errorf("event failed: %v", err)
		}
		return nil
	}
}

func getKubeConfig(log *logging.Logger, kubepath string) (*rest.Config, error) {
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
	log.Debug("using in cluster kubeconfig")
	return inClusterConfig, nil
}
