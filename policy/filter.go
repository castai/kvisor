package policy

import (
	"fmt"
	"golang.stackrox.io/kube-linter/pkg/k8sutil"
)

type objectFilter func(k8sutil.Object) (bool, string)

func skipObjectsWithOwners(obj k8sutil.Object) (bool, string) {
	if len(obj.GetOwnerReferences()) > 0 {
		return true, fmt.Sprintf(
			"obj %q is not validated because it has %d owner(s)",
			obj.GetName(),
			len(obj.GetOwnerReferences()),
		)
	}

	return false, ""
}
