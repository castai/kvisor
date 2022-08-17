package types

import "fmt"

type LintCheck struct {
	ID       string
	Message  string
	Resource Resource
	Linter   string
	Failed   bool
	Category string
}

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

func (c *LintCheck) ObjectKey() string {
	return c.Resource.ObjectKey()
}

type CheckMeta struct {
	DisplayName string
	Description string
	Severity    float32 // TODO: remove after CVSS3.1 Vectors are filled in
	Category    string
	CVSS3Vector string
}
