package pipeline

import "regexp"

// podVolumeMountRegex matches kubelet pod volume mount paths.
// Format: /var/lib/kubelet/pods/<pod-uid>/volumes/<plugin>/<volume-name>
var podVolumeMountRegex = regexp.MustCompile(
	`/var/lib/kubelet/pods/([a-f0-9-]+)/volumes/([^/]+)/([^/]+)`,
)

// VolumePathInfo contains extracted information from a volume mount path.
type VolumePathInfo struct {
	PodUID       string
	VolumePlugin string
	VolumeName   string
}

// ParseVolumeMountPath extracts pod and volume info from a kubelet mount path.
// Returns nil if the path is not a pod volume mount.
func ParseVolumeMountPath(mountPath string) *VolumePathInfo {
	matches := podVolumeMountRegex.FindStringSubmatch(mountPath)
	if len(matches) != 4 {
		return nil
	}
	return &VolumePathInfo{
		PodUID:       matches[1],
		VolumePlugin: matches[2],
		VolumeName:   matches[3],
	}
}
