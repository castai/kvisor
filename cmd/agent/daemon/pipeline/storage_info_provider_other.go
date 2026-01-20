//go:build !linux

package pipeline

func (s *SysfsStorageInfoProvider) findDMDeviceByMajorMinor(hostMapperPath string, rdev int32) []string {
	return nil
}
