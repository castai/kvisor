//go:build linux

package ebpftracer

import (
	"fmt"
	"os"
	"syscall"
)

func mountCgroup2(mountPoint string) error {
	err := os.Mkdir(mountPoint, 0755)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("creating directory at %q: %w", mountPoint, err)
	}
	// https://docs.kernel.org/admin-guide/cgroup-v2.html#mounting
	err = syscall.Mount("none", mountPoint, "cgroup2", 0, "")
	if err != nil {
		return fmt.Errorf("mounting cgroup2 at %q: %w", mountPoint, err)
	}
	return nil
}
