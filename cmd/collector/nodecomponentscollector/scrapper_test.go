package nodecomponentscollector

import (
	"context"
	"testing"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes/fake"
)

func TestScrapper(t *testing.T) {
	clientset := fake.NewClientset()
	scrapper := NewScrapper(&mockCastaiClient{}, clientset, &mockConfigRegistry{}, "test-id", "test-node")

	t.Run("get node component", func(t *testing.T) {
		r := require.New(t)

		component, err := scrapper.getKubeNodeComponent(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBELET)
		r.NoError(err)

		r.Equal("./config_rules/config.yaml", component.ConfigFile.Path)
		r.Equal(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBELET, component.Name)
		r.Equal(castaipb.KubeNodeComponents_CONFIG_TYPE_AZURE_JSON, component.ConfigType)
	})

	t.Run("send report", func(t *testing.T) {
		r := require.New(t)
		ctx := context.Background()

		report := &castaipb.KubeNodeComponents{}
		err := scrapper.sendReport(ctx, report)
		r.NoError(err)
	})
}

type mockCastaiClient struct{}

func (m *mockCastaiClient) KubeNodeComponentsIngest(ctx context.Context, in *castaipb.KubeNodeComponents, opts ...grpc.CallOption) (*castaipb.KubeNodeComponentsIngestResponse, error) {
	return nil, nil
}

type mockConfigRegistry struct{}

func (c *mockConfigRegistry) GetConfigs(component castaipb.KubeNodeComponents_ComponentName) []Config {
	return []Config{
		{Component: castaipb.KubeNodeComponents_COMPONENT_NAME_KUBELET, Path: "./config_rules/config.yaml", Type: castaipb.KubeNodeComponents_CONFIG_TYPE_AZURE_JSON},
	}
}
