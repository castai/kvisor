package nodecomponentscollector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
)

type Scrapper struct {
	castaiClient   castAIClient
	configRegistry configRegistry
	ks8Client      kubernetes.Interface
	nodeId         string
	nodeName       string
}

type castAIClient interface {
	KubeNodeComponentsIngest(ctx context.Context, in *castaipb.KubeNodeComponents, opts ...grpc.CallOption) (*castaipb.KubeNodeComponentsIngestResponse, error)
}

type configRegistry interface {
	GetConfigs(component castaipb.KubeNodeComponents_ComponentName) []Config
}

func NewScrapper(castaiClient castAIClient, ks8Client kubernetes.Interface, configRegistry configRegistry, nodeId, nodeName string) *Scrapper {
	return &Scrapper{castaiClient: castaiClient, configRegistry: configRegistry, ks8Client: ks8Client, nodeId: nodeId, nodeName: nodeName}
}

func (s *Scrapper) Run(ctx context.Context) error {
	fmt.Printf("starting node collector on node %s\n", s.nodeName)

	report, err := s.generateReport(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	err = s.sendReport(ctx, report)
	if err != nil {
		return fmt.Errorf("failed to send report: %w", err)
	}

	return nil
}

// generateReport returns a report with config files for Kubernetes node components
func (s *Scrapper) generateReport(ctx context.Context) (*castaipb.KubeNodeComponents, error) {
	report := &castaipb.KubeNodeComponents{
		Node: &castaipb.KubeNodeComponents_Node{Id: s.nodeId, Name: s.nodeName},
	}

	// Kubernetes component
	kubernetesComponent, err := s.getKubeNodeComponent(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBERNETES)
	if err != nil {
		return nil, fmt.Errorf("generate kubernetes component: %w", err)
	}
	report.Components = append(report.Components, kubernetesComponent)

	// Kubelet component
	kubeletComponent, err := s.getKubeNodeComponent(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBELET)
	if err != nil {
		return nil, fmt.Errorf("generate kubelet component: %w", err)
	}
	if kubeletComponent == nil {
		kubeletComponent = &castaipb.KubeNodeComponents_NodeComponent{
			Name: castaipb.KubeNodeComponents_COMPONENT_NAME_KUBELET,
		}
	}
	kubeletComponent.ConfigData, err = s.getNodeConfigData(ctx)
	if err != nil {
		return nil, fmt.Errorf("get kubelet config data: %w", err)
	}
	report.Components = append(report.Components, kubeletComponent)

	// Proxy component
	proxyComponent, err := s.getKubeNodeComponent(castaipb.KubeNodeComponents_COMPONENT_NAME_PROXY)
	if err != nil {
		return nil, fmt.Errorf("generate proxy component: %w", err)
	}
	report.Components = append(report.Components, proxyComponent)

	return report, nil
}

// sendReport sends a generated report to Runtime API backend
func (s *Scrapper) sendReport(ctx context.Context, report *castaipb.KubeNodeComponents) error {
	_, err := s.castaiClient.KubeNodeComponentsIngest(ctx, report)
	return err
}

// getKubeNodeComponent returns a node component for by given component name
func (s *Scrapper) getKubeNodeComponent(component castaipb.KubeNodeComponents_ComponentName) (*castaipb.KubeNodeComponents_NodeComponent, error) {
	for _, config := range s.configRegistry.GetConfigs(component) {
		configFile, err := s.getFileConfigFile(config.Path)
		if err != nil {
			return nil, err
		}
		if configFile == nil {
			// file not found
			continue
		}

		return &castaipb.KubeNodeComponents_NodeComponent{
			Name:       config.Component,
			ConfigType: config.Type,
			ConfigFile: configFile,
		}, nil
	}

	return nil, nil
}

// getNodeConfigData returns kubernetes API node response as encoded payload
func (s *Scrapper) getNodeConfigData(ctx context.Context) (*castaipb.KubeNodeComponents_ConfigData, error) {
	req := s.ks8Client.CoreV1().RESTClient().Get().Resource("nodes").
		Name(s.nodeName).SubResource("proxy").Suffix("configz")
	result := req.Do(ctx)
	if result.Error() != nil {
		return nil, fmt.Errorf("calling k8s node api: %w", result.Error())
	}

	content, err := result.Raw()
	if err != nil {
		return nil, fmt.Errorf("getting node config content: %w", err)
	}

	// calculate content hash
	d := sha256.New()
	_, err = d.Write(content)
	if err != nil {
		return nil, fmt.Errorf("calculating content hash: %w", err)
	}

	return &castaipb.KubeNodeComponents_ConfigData{
		Content: content,
		Hash:    fmt.Sprintf("sha256:%s", hex.EncodeToString(d.Sum(nil))),
		Source:  castaipb.KubeNodeComponents_CONFIG_SOURCE_API,
	}, nil
}

// getFileConfigFile returns a metadata as ConfigFile for a given file if it exists
func (s *Scrapper) getFileConfigFile(filename string) (*castaipb.KubeNodeComponents_ConfigFile, error) {
	fileStats, err := os.Stat(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	fileSys := fileStats.Sys()
	return &castaipb.KubeNodeComponents_ConfigFile{
		Path: filename,
		Mode: uint32(fileSys.(*syscall.Stat_t).Mode),
		Gid:  fileSys.(*syscall.Stat_t).Gid,
		Uid:  fileSys.(*syscall.Stat_t).Uid,
	}, nil
}
