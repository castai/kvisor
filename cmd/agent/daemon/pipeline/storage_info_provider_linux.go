//go:build linux

package pipeline

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// findDMDeviceByMajorMinor searches for the corresponding /dev/dm-* device
// with the same major:minor numbers as the given device Rdev.
func (s *SysfsStorageInfoProvider) findDMDeviceByMajorMinor(hostMapperPath string, rdev uint64) []string {
	devDirPath := filepath.Join(s.hostRootPath, "/dev")
	entries, err := os.ReadDir(devDirPath)
	if err != nil {
		s.log.Errorf("failed to read /dev directory: %v", err)
		return nil
	}

	targetMajor := unix.Major(rdev)
	targetMinor := unix.Minor(rdev)

	for _, entry := range entries {
		// We only care about device mapper devices.
		if !strings.HasPrefix(entry.Name(), "dm-") {
			continue
		}

		dmDevicePath := filepath.Join(devDirPath, entry.Name())
		var dmStat unix.Stat_t
		if err := unix.Stat(dmDevicePath, &dmStat); err != nil {
			continue
		}

		// Check if it's a block device and has matching major:minor
		if dmStat.Mode&unix.S_IFBLK != 0 {
			dmMajor := unix.Major(dmStat.Rdev)
			dmMinor := unix.Minor(dmStat.Rdev)
			if dmMajor == targetMajor && dmMinor == targetMinor {
				return []string{"/dev/" + entry.Name()}
			}
		}
	}

	s.log.Errorf("no matching /dev/dm-* device found for %s (major=%d, minor=%d)",
		hostMapperPath, targetMajor, targetMinor)
	return nil
}
