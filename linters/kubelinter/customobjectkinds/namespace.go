package customobjectkinds

import (
	"golang.stackrox.io/kube-linter/pkg/objectkinds"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// Namespace represents Kubernetes Namespace objects. Case sensitive.
	Namespace = "Namespace"
)

var (
	namespaceGVK = corev1.SchemeGroupVersion.WithKind("Namespace")
)

func RegisterNamespaceKind() {
	objectkinds.RegisterObjectKind(Namespace, objectkinds.MatcherFunc(func(gvk schema.GroupVersionKind) bool {
		return gvk == namespaceGVK
	}))
}
