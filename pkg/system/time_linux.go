package system

import (
	"sync"
	"time"

	"github.com/tklauser/go-sysconf"
	"golang.org/x/sys/unix"
)

var sysconfClockTickOnce, bootTimeOnce sync.Once

// The default clock tick in sysconf is 100. Never use this constant directly and only access the
// value via `getClockTicks`, as the user might change this value.
var sysconfClockTick int64 = 100
var bootTime time.Time

func GetClockTicks() int64 {
	sysconfClockTickOnce.Do(func() {
		ticks, err := sysconf.Sysconf(sysconf.SC_CLK_TCK)
		if err == nil {
			sysconfClockTick = ticks
		}
	})

	return sysconfClockTick
}

func GetBootTime() time.Time {
	bootTimeOnce.Do(func() {
		var ts unix.Timespec
		err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
		if err != nil {
			return
		}

		uptime := time.Duration(ts.Nano()) * time.Nanosecond
		bootTime = time.Now().Add(-uptime).UTC()
	})

	return bootTime
}
