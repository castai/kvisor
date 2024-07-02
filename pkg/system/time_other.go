//go:build !linux
package system

import "time"

func GetClockTicks() int64 {
	return 100
}

func GetBootTime() time.Time {
	return time.Now()
}
