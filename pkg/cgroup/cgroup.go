package cgroup

import (
	"os"
	"path"
	"time"

	"k8s.io/klog/v2"
)

type Cgroup struct {
	Id               uint64
	Version          Version
	ContainerRuntime ContainerRuntimeID
	ContainerID      string
	Path             string

	subsystems map[string]string
	cgRoot     string
}

func (cg *Cgroup) CreatedAt() time.Time {
	p := path.Join(cg.cgRoot, cg.subsystems[""]) //v2
	if cg.Version == V1 {
		p = path.Join(cg.cgRoot, "cpu", cg.subsystems["cpu"])
	}
	fi, err := os.Stat(p)
	if err != nil {
		if !os.IsNotExist(err) {
			klog.Errorln(err)
		}
		return time.Time{}
	}
	return fi.ModTime()
}
