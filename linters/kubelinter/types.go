package kubelinter

import (
	"sync"

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

func newDeltaState() *deltaState {
	return &deltaState{
		objectMap: make(map[object]struct{}),
		mutex:     sync.Mutex{},
	}
}

type deltaState struct {
	objectMap map[object]struct{}
	mutex     sync.Mutex
}

func (d *deltaState) add(o object) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.objectMap[o] = struct{}{}
}

func (d *deltaState) delete(o object) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	delete(d.objectMap, o)
}

func (d *deltaState) flush() []object {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer func() {
		d.objectMap = make(map[object]struct{})
	}()

	res := make([]object, 0, len(d.objectMap))
	for o := range d.objectMap {
		res = append(res, o)
	}

	return res
}
