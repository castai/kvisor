package admissionpolicy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestValidator(t *testing.T) {
	r := require.New(t)

	testEnv := &envtest.Environment{
		Scheme: clientgoscheme.Scheme,
		ControlPlane: envtest.ControlPlane{
			APIServer: &envtest.APIServer{
				Args: []string{
					"--feature-gates=ValidatingAdmissionPolicy=true",
					"--runtime-config=admissionregistration.k8s.io/v1beta1=true",
				},
			},
		},
	}
	cfg, err := testEnv.Start()
	r.NoError(err)
	t.Cleanup(func() {
		err := testEnv.Stop()
		if err != nil {
			t.Fatalf("failed to stop test environment: %v", err)
		}
	})
	err = EnsurePolicies(context.Background(), cfg)
	r.NoError(err)

	validator, err := NewValidator(cfg)
	r.NoError(err)
	r.True(validator.WaitForReady())

	stop := make(chan struct{})
	err = validator.Start(stop)
	r.NoError(err)
	t.Cleanup(func() {
		close(stop)
	})

	tt := []struct {
		name    string
		object  runtime.Object
		allowed bool
	}{
		{
			name:    "docker socket pod",
			allowed: false,
			object: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "docker-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "docker",
							Image: "docker",
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "docker-socket",
									MountPath: "/var/run/docker.sock",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "docker-socket",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run/docker.sock",
								},
							},
						},
					},
				},
			},
		},
		{
			name:    "nginx pod",
			allowed: true,
			object: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx",
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.Validate(context.Background(), tc.object)
			if tc.allowed {
				r.NoError(err)
			} else {
				r.Error(err)
			}
		})
	}
}
