package types

import "fmt"

type Type string

const (
	TypeGCP   Type = "gcp"
	TypeAWS   Type = "aws"
	TypeAzure Type = "azure"

	DomainGCP string = "googleapis.com"
	DomainAWS string = "amazonaws.com"
)

func NewProviderType(provider string) (Type, error) {
	switch provider {
	case "gcp", "gke":
		return TypeGCP, nil
	case "aws", "eks":
		return TypeAWS, nil
	case "azure", "aks":
		return TypeAzure, nil
	default:
		return "", fmt.Errorf("unknown cloud provider: %s", provider)
	}
}

func (t Type) KubernetesType() string {
	switch t {
	case TypeGCP:
		return "gke"
	case TypeAWS:
		return "eks"
	case TypeAzure:
		return "aks"
	default:
		return ""
	}
}
