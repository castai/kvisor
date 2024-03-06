package additionalcapabilities

import (
	"golang.stackrox.io/kube-linter/pkg/config"
)

func Check() *config.Check {
	return &config.Check{
		Name:        "additional-capabilities",
		Description: "Checks if pod has additional capabilities.",
		Template:    "verify-container-capabilities",
		Params: map[string]interface{}{
			"forbiddenCapabilities": []string{"all"},
		},
	}
}
