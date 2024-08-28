package system

import "time"

func TicksToDuration(ticks uint64) time.Duration {
	seconds := uint64(ticks / uint64(GetClockTicks()))

	return time.Duration(seconds) * time.Second // nolint:gosec
}
