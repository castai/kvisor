package kubelinter

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	casttypes "github.com/castai/sec-agent/castai"
)

func TestLinter(t *testing.T) {
	t.Run("checks for containerd sock mount", func(t *testing.T) {
		r := require.New(t)

		linter, err := New(lo.Keys(casttypes.LinterRuleMap))
		r.NoError(err)

		checks, err := linter.Run([]lintcontext.Object{{
			K8sObject: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test_pod",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test",
							Image: "test-image",
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "containerd.sock",
									MountPath: "/var/lib/containerd.sock",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "containerd.sock",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/containerd.sock",
								},
							},
						},
					},
				},
			},
		}})
		r.NoError(err)
		r.Contains(checks[0].Failed.Rules(), "containerd-sock")
	})
}
