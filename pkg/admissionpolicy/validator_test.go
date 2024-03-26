package admissionpolicy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestValidator(t *testing.T) {
	ctx := context.Background()
	r := require.New(t)

	testEnv := &envtest.Environment{
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

	// Load policies into cluster
	err = EnsurePolicies(ctx, cfg)
	r.NoError(err)

	// Bind some of the policies for the test cases
	cli := kubernetes.NewForConfigOrDie(cfg)
	_, err = cli.AdmissionregistrationV1beta1().
		ValidatingAdmissionPolicyBindings().
		Create(ctx,
			&v1beta1.ValidatingAdmissionPolicyBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "docker-socket-mount",
				},
				Spec: v1beta1.ValidatingAdmissionPolicyBindingSpec{
					PolicyName:        "docker-sock-mount.policies.cast.ai",
					ValidationActions: []v1beta1.ValidationAction{v1beta1.Deny},
				},
			},
			metav1.CreateOptions{},
		)
	r.NoError(err)
	_, err = cli.AdmissionregistrationV1beta1().
		ValidatingAdmissionPolicyBindings().
		Create(ctx,
			&v1beta1.ValidatingAdmissionPolicyBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "has-security-context",
				},
				Spec: v1beta1.ValidatingAdmissionPolicyBindingSpec{
					PolicyName:        "has-security-context.policies.cast.ai",
					ValidationActions: []v1beta1.ValidationAction{v1beta1.Deny},
				},
			},
			metav1.CreateOptions{},
		)
	r.NoError(err)

	validator, err := NewValidator(cfg)
	r.NoError(err)

	stop := make(chan struct{})
	go validator.Run(stop)
	t.Cleanup(func() { close(stop) })

	timeout := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for validator to become ready")
		default:
		}
		if validator.HasSynced() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

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
