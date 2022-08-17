package kubelinter

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var rules = []string{
	"dangling-service",
	"deprecated-service-account-field",
	"docker-sock",
	"drop-net-raw-capability",
	"env-var-secret",
	"exposed-services",
	"host-ipc",
	"host-network",
	"host-pid",
	"invalid-target-ports",
	"latest-tag",
	"mismatching-selector",
	"no-anti-affinity",
	"no-liveness-probe",
	"no-read-only-root-fs",
	"no-readiness-probe",
	"no-rolling-update-strategy",
	"privilege-escalation-container",
	"privileged-container",
	"privileged-ports",
	"run-as-non-root",
	"sensitive-host-mounts",
	"ssh-port",
	"unsafe-proc-mount",
	"unsafe-sysctls",
	"unset-memory-requirements",
	"use-namespace",
	"writable-host-mount",
}

type event string

const (
	eventAdd    event = "add"
	eventDelete event = "delete"
	eventUpdate event = "update"
)

type object interface {
	runtime.Object
	metav1.Object
}

type queueItem struct {
	obj   object
	event event
}

func (i *queueItem) ObjectKey() string {
	kind := i.obj.GetObjectKind().GroupVersionKind()
	return fmt.Sprintf(
		"%s/%s/%s/%s",
		kind.Version,
		kind.Kind,
		i.obj.GetNamespace(),
		i.obj.GetName(),
	)
}
