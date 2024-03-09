//go:build !linux

package kernel

import "errors"

func currentVersionUname() (Version, error) {
	return Version{}, errors.New("should not be used")
}
