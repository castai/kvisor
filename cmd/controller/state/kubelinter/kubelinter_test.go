package kubelinter

import (
	rbacv1 "k8s.io/api/rbac/v1"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLinter(t *testing.T) {
	t.Run("checks for containerd sock mount", func(t *testing.T) {
		r := require.New(t)

		linter, err := New(lo.Keys(LinterRuleMap))
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

	t.Run("checks for additional capabilities", func(t *testing.T) {
		r := require.New(t)

		linter, err := New(lo.Keys(LinterRuleMap))
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
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{
										"NET_ADMIN",
									},
								},
							},
						},
					},
				},
			},
		}})
		r.NoError(err)
		r.Contains(checks[0].Failed.Rules(), "additional-capabilities")
	})

	t.Run("checks for bindings", func(t *testing.T) {
		r := require.New(t)

		linter, err := New(lo.Keys(LinterRuleMap))
		r.NoError(err)

		checks, err := linter.Run([]lintcontext.Object{{
			K8sObject: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test_role_binding",
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRoleBinding",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "Group",
						Name: "system:authenticated",
					},
				},
				RoleRef: rbacv1.RoleRef{
					Kind: "Role",
					Name: "testrole",
				},
			},
		}})

		r.NoError(err)
		r.Len(checks, 1)
		r.Contains(checks[0].Failed.Rules(), "system-authenticated")
	})
}
