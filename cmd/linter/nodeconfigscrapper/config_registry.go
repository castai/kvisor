package nodeconfigscrapper

import (
	_ "embed"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
)

//go:embed config_rules/config.yaml
var configRulesData []byte

type ConfigRegistry struct {
	Node struct {
		Kubernetes struct {
			AzureJSON     string `yaml:"azurejson"`
			DefaultConfig string `yaml:"defaultconf"`
		} `yaml:"kubernetes"`
		Kubelet struct {
			Kubeconfig        []string `yaml:"kubeconfig"`
			Configs           []string `yaml:"confs"`
			DefaultConfig     string   `yaml:"defaultconf"`
			DefaultKubeConfig string   `yaml:"defaultkubeconfig"`
		} `yaml:"kubelet"`
		Proxy struct {
			Kubeconfig        []string `yaml:"kubeconfig"`
			Configs           []string `yaml:"confs"`
			DefaultConfig     string   `yaml:"defaultconf"`
			DefaultKubeConfig string   `yaml:"defaultkubeconfig"`
		} `yaml:"proxy"`
	} `yaml:"node"`

	configs []Config
}

type Config struct {
	Path      string
	Component castaipb.KubeNodeComponents_ComponentName
	Type      castaipb.KubeNodeComponents_ConfigType
}

func NewConfigRegistry() *ConfigRegistry {
	cr := &ConfigRegistry{}

	err := cr.parseConfigRules(configRulesData)
	if err != nil {
		return nil
	}

	return cr
}

func (c *ConfigRegistry) parseConfigRules(data []byte) error {
	err := yaml.Unmarshal(data, &c)
	if err != nil {
		return err
	}

	c.categorizeConfigs()
	return nil
}

// GetConfigs returns a list of config files with types for a given component
func (c *ConfigRegistry) categorizeConfigs() {
	var configs []Config

	// Kubernetes
	configs = append(configs, convertToConfig(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBERNETES, castaipb.KubeNodeComponents_CONFIG_TYPE_AZURE_JSON, c.Node.Kubernetes.AzureJSON)...)
	configs = append(configs, convertToConfig(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBERNETES, castaipb.KubeNodeComponents_CONFIG_TYPE_CONF, c.Node.Kubernetes.DefaultConfig)...)

	// Kubelet
	configs = append(configs, convertToConfig(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBELET, castaipb.KubeNodeComponents_CONFIG_TYPE_CONF, c.Node.Kubelet.Configs...)...)
	configs = append(configs, convertToConfig(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBELET, castaipb.KubeNodeComponents_CONFIG_TYPE_KUBECONFIG, c.Node.Kubelet.Kubeconfig...)...)
	configs = append(configs, convertToConfig(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBELET, castaipb.KubeNodeComponents_CONFIG_TYPE_CONF, c.Node.Kubelet.DefaultConfig)...)
	configs = append(configs, convertToConfig(castaipb.KubeNodeComponents_COMPONENT_NAME_KUBELET, castaipb.KubeNodeComponents_CONFIG_TYPE_KUBECONFIG, c.Node.Kubelet.DefaultKubeConfig)...)

	// Proxy
	configs = append(configs, convertToConfig(castaipb.KubeNodeComponents_COMPONENT_NAME_PROXY, castaipb.KubeNodeComponents_CONFIG_TYPE_CONF, c.Node.Proxy.Configs...)...)
	configs = append(configs, convertToConfig(castaipb.KubeNodeComponents_COMPONENT_NAME_PROXY, castaipb.KubeNodeComponents_CONFIG_TYPE_KUBECONFIG, c.Node.Proxy.Kubeconfig...)...)
	configs = append(configs, convertToConfig(castaipb.KubeNodeComponents_COMPONENT_NAME_PROXY, castaipb.KubeNodeComponents_CONFIG_TYPE_CONF, c.Node.Proxy.DefaultConfig)...)
	configs = append(configs, convertToConfig(castaipb.KubeNodeComponents_COMPONENT_NAME_PROXY, castaipb.KubeNodeComponents_CONFIG_TYPE_KUBECONFIG, c.Node.Proxy.DefaultKubeConfig)...)

	c.configs = lo.Filter(configs, func(c Config, _ int) bool { return c.Path != "" })
}

func (c *ConfigRegistry) GetConfigs(component castaipb.KubeNodeComponents_ComponentName) []Config {
	return lo.Filter(c.configs, func(conf Config, _ int) bool { return conf.Component == component })
}

func convertToConfig(component castaipb.KubeNodeComponents_ComponentName, configType castaipb.KubeNodeComponents_ConfigType, paths ...string) []Config {
	return lo.Map(paths, func(path string, _ int) Config { return Config{Path: path, Component: component, Type: configType} })
}
