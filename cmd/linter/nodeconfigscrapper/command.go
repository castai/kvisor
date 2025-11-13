package nodeconfigscrapper

import (
	"errors"
	"fmt"
	"os"

	"github.com/castai/kvisor/cmd/linter/nodeconfigscrapper/config"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"
)

func NewRunCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "node-config-scrapper",
		Short: "Run node configuration scrapper",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.FromEnv()
			if err != nil {
				exitWithError(err)
			}

			castaiClientCfg, err := castai.NewConfigFromEnv(cfg.CastaiGRPCInsecure)
			if err != nil {
				exitWithError(fmt.Errorf("failed to initialize CAST AI client config: %w", err))
			}
			castaiClient, err := castai.NewClient(fmt.Sprintf("kvisor-node-config-scrapper/%s", version), castaiClientCfg)
			if err != nil {
				exitWithError(err)
			}
			defer castaiClient.Close()

			kubeConfig, err := getKubeConfig(cfg.Kubeconfig)
			if err != nil {
				exitWithError(err)
			}
			kubeConfig.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(float32(25), 100)
			clientset, err := kubernetes.NewForConfig(kubeConfig)
			if err != nil {
				exitWithError(err)
			}

			configRegistry := NewConfigRegistry()
			if configRegistry == nil {
				exitWithError(errors.New("error parsing config rules"))
			}

			scrapper := NewScrapper(castaiClient.GRPC, clientset, configRegistry, cfg.NodeName)
			err = scrapper.Run(cmd.Context())
			if err != nil {
				exitWithError(err)
			}
		},
	}
}

func getKubeConfig(configPath string) (*rest.Config, error) {
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("reading kubeconfig at %s: %w", configPath, err)
		}
		restConfig, err := clientcmd.RESTConfigFromKubeConfig(data)
		if err != nil {
			return nil, fmt.Errorf("building rest config from kubeconfig at %s: %w", configPath, err)
		}
		return restConfig, nil
	}

	inClusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return inClusterConfig, nil
}

func exitWithError(err error) {
	fmt.Fprintf(os.Stderr, "\n%v\n", err)
	// flush before exit non-zero
	glog.Flush()
	os.Exit(1)
}
