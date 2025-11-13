package nodeconfigscrapper

import (
	"slices"
	"testing"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/stretchr/testify/require"
)

func TestConfigRegistry(t *testing.T) {
	t.Run("get config files by component name", func(t *testing.T) {
		r := require.New(t)

		cr := NewConfigRegistry()
		var configs []Config

		configs = cr.GetConfigs(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBELET)
		r.True(slices.Contains(configs, Config{Path: "/etc/kubernetes/kubelet-config.yaml", Component: castaipb.KubeNodeComponents_COMPONENT_NAME_KUBELET, Type: castaipb.KubeNodeComponents_CONFIG_TYPE_CONF}))

		configs = cr.GetConfigs(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBERNETES)
		r.True(slices.Contains(configs, Config{Path: "/etc/kubernetes/config", Component: castaipb.KubeNodeComponents_COMPONENT_NAME_KUBERNETES, Type: castaipb.KubeNodeComponents_CONFIG_TYPE_CONF}))
		r.True(slices.Contains(configs, Config{Path: "/etc/kubernetes/azure.json", Component: castaipb.KubeNodeComponents_COMPONENT_NAME_KUBERNETES, Type: castaipb.KubeNodeComponents_CONFIG_TYPE_AZURE_JSON}))

		configs = cr.GetConfigs(castaipb.KubeNodeComponents_COMPONENT_NAME_PROXY)
		r.True(slices.Contains(configs, Config{Path: "/etc/kubernetes/proxy.conf", Component: castaipb.KubeNodeComponents_COMPONENT_NAME_PROXY, Type: castaipb.KubeNodeComponents_CONFIG_TYPE_KUBECONFIG}))
	})
}
