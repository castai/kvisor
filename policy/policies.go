package policy

import (
	"embed"
	"fmt"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/client-go/kubernetes/scheme"
)

//go:embed policies/*.yaml
var embeddedPolicies embed.FS

func loadPolicies() ([]admissionregistrationv1beta1.ValidatingAdmissionPolicy, error) {
	entries, err := embeddedPolicies.ReadDir("policies")
	if err != nil {
		return nil, fmt.Errorf("reading embedded policies directory: %w", err)
	}

	var policies []admissionregistrationv1beta1.ValidatingAdmissionPolicy
	decode := scheme.Codecs.UniversalDeserializer().Decode

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := "policies/" + entry.Name()
		content, err := embeddedPolicies.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("reading embedded policies file %s: %w", filename, err)
		}

		obj, _, err := decode(content, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("decoding embedded policy %s: %w", filename, err)
		}

		policies = append(policies, *obj.(*admissionregistrationv1beta1.ValidatingAdmissionPolicy))
	}

	return policies, nil
}
