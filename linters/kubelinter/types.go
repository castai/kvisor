package kubelinter

import (
	"fmt"
	"sync"

	"github.com/castai/sec-agent/controller"
	"github.com/castai/sec-agent/types"
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

type LintCheck struct {
	ID       string
	Message  string
	Resource types.Resource
	Linter   string
	Failed   bool
	Category string
}

func (c *LintCheck) ObjectKey() string {
	return c.Resource.ObjectKey()
}

func newDeltaState() *deltaState {
	return &deltaState{
		objectMap: make(map[string]controller.Object),
		mu:        sync.Mutex{},
	}
}

type deltaState struct {
	objectMap map[string]controller.Object
	mu        sync.Mutex
}

func (d *deltaState) upsert(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
	fmt.Println(key)
	d.objectMap[key] = o
}

func (d *deltaState) delete(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.objectMap, controller.ObjectKey(o))
}

func (d *deltaState) flush() []controller.Object {
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		d.objectMap = make(map[string]controller.Object)
	}()

	res := make([]controller.Object, 0, len(d.objectMap))
	for _, o := range d.objectMap {
		res = append(res, o)
	}

	return res
}
