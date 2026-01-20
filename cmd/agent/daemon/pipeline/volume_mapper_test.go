package pipeline

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVolumeMountPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected *VolumePathInfo
	}{
		{
			name: "CSI volume mount",
			path: "/var/lib/kubelet/pods/3e61c214-bc3e-d9ff-81e2-1474dd6cba17/volumes/kubernetes.io~csi/pvc-abc123",
			expected: &VolumePathInfo{
				PodUID:       "3e61c214-bc3e-d9ff-81e2-1474dd6cba17",
				VolumePlugin: "kubernetes.io~csi",
				VolumeName:   "pvc-abc123",
			},
		},
		{
			name: "EmptyDir volume mount",
			path: "/var/lib/kubelet/pods/abc-def-123/volumes/kubernetes.io~empty-dir/cache",
			expected: &VolumePathInfo{
				PodUID:       "abc-def-123",
				VolumePlugin: "kubernetes.io~empty-dir",
				VolumeName:   "cache",
			},
		},
		{
			name: "HostPath volume mount",
			path: "/var/lib/kubelet/pods/12345678-1234-1234-1234-123456789012/volumes/kubernetes.io~host-path/host-data",
			expected: &VolumePathInfo{
				PodUID:       "12345678-1234-1234-1234-123456789012",
				VolumePlugin: "kubernetes.io~host-path",
				VolumeName:   "host-data",
			},
		},
		{
			name: "ConfigMap volume mount",
			path: "/var/lib/kubelet/pods/aabbccdd-1122-3344-5566-778899aabbcc/volumes/kubernetes.io~configmap/config",
			expected: &VolumePathInfo{
				PodUID:       "aabbccdd-1122-3344-5566-778899aabbcc",
				VolumePlugin: "kubernetes.io~configmap",
				VolumeName:   "config",
			},
		},
		{
			name:     "Root filesystem - not a pod volume",
			path:     "/",
			expected: nil,
		},
		{
			name:     "Kubelet directory - not a volume mount",
			path:     "/var/lib/kubelet",
			expected: nil,
		},
		{
			name:     "Containerd directory - not a pod volume",
			path:     "/var/lib/containerd",
			expected: nil,
		},
		{
			name:     "Regular mount point - not a pod volume",
			path:     "/mnt/data",
			expected: nil,
		},
		{
			name:     "Pod directory without volumes - not a volume mount",
			path:     "/var/lib/kubelet/pods/abc-123",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseVolumeMountPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}
