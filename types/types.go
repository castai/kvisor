package types

import "fmt"

type Resource struct {
	ObjectMeta ObjectMeta
	ObjectType ObjectType
}

type ObjectMeta struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type ObjectType struct {
	APIVersion string `json:"APIVersion"`
	Kind       string `json:"kind"`
}

func (r Resource) ObjectKey() string {
	return fmt.Sprintf(
		"%s/%s/%s/%s",
		r.ObjectType.APIVersion,
		r.ObjectType.Kind,
		r.ObjectMeta.Namespace,
		r.ObjectMeta.Name,
	)
}
