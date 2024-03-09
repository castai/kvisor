package kernel

import (
	"strings"
	"syscall"
)

func currentVersionUname() (Version, error) {
	var buf syscall.Utsname
	if err := syscall.Uname(&buf); err != nil {
		return Version{}, err
	}
	releaseString := strings.Trim(utsnameStr(buf.Release[:]), "\x00")
	return KernelVersionFromReleaseString(releaseString)
}
