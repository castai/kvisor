//go:build !linux

package ebpftracer

import "errors"

func mountCgroup2(mountPoint string) error {
	return errors.New("should not be used")
}
