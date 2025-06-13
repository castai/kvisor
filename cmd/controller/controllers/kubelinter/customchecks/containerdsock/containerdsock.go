package containerdsock

import (
	"golang.stackrox.io/kube-linter/pkg/config"
)

func Check() *config.Check {
	return &config.Check{
		Name:        "containerd-sock",
		Description: "Alert on deployments with containerd.sock mounted in containers.",
		Template:    "host-mounts",
		Params: map[string]interface{}{
			"dirs": []string{"containerd.sock$"},
		},
	}
}
