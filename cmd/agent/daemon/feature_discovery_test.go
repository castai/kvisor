package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/castai/logging"
)

func TestIsDCGMExporter(t *testing.T) {
	tests := []struct {
		name   string
		ds     appsv1.DaemonSet
		expect bool
	}{
		{
			name: "detected by known image prefix",
			ds:   makeDSWithContainer(corev1.Container{Image: "nvcr.io/nvidia/k8s/dcgm-exporter:3.3.0"}),
			expect: true,
		},
		{
			name: "detected by nvidia/dcgm-exporter image",
			ds:   makeDSWithContainer(corev1.Container{Image: "nvidia/dcgm-exporter:latest"}),
			expect: true,
		},
		{
			name: "detected by gke image",
			ds:   makeDSWithContainer(corev1.Container{Image: "nvidia/gke-dcgm-exporter:3.1.0"}),
			expect: true,
		},
		{
			name: "detected by command substring",
			ds:   makeDSWithContainer(corev1.Container{Image: "some-image:v1", Command: []string{"/bin/bash", "-c", "dcgm-exporter --metrics"}}),
			expect: true,
		},
		{
			name: "detected by args substring",
			ds:   makeDSWithContainer(corev1.Container{Image: "some-image:v1", Command: []string{"/bin/bash", "-c"}, Args: []string{"hostname $NODE_NAME; dcgm-exporter -f /etc/dcgm-exporter/counters.csv"}}),
			expect: true,
		},
		{
			name: "not matched",
			ds:   makeDSWithContainer(corev1.Container{Image: "some-other-image:v1", Command: []string{"prometheus"}}),
			expect: false,
		},
		{
			name:   "empty containers",
			ds:     appsv1.DaemonSet{},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDCGMExporter(tt.ds)
			if got != tt.expect {
				t.Errorf("isDCGMExporter() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestExtractDCGMSelector(t *testing.T) {
	tests := []struct {
		name   string
		ds     appsv1.DaemonSet
		expect string
	}{
		{
			name: "app.kubernetes.io/name from matchLabels",
			ds: appsv1.DaemonSet{
				Spec: appsv1.DaemonSetSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app.kubernetes.io/name": "dcgm-exporter"},
					},
				},
			},
			expect: "app.kubernetes.io/name=dcgm-exporter",
		},
		{
			name: "app label from matchLabels (fallback)",
			ds: appsv1.DaemonSet{
				Spec: appsv1.DaemonSetSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "dcgm"},
					},
				},
			},
			expect: "app=dcgm",
		},
		{
			name: "app.kubernetes.io/name from metadata labels",
			ds: appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app.kubernetes.io/name": "dcgm-exporter"},
				},
			},
			expect: "app.kubernetes.io/name=dcgm-exporter",
		},
		{
			name: "app label from metadata (last fallback)",
			ds: appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "dcgm"},
				},
			},
			expect: "app=dcgm",
		},
		{
			name:   "no labels",
			ds:     appsv1.DaemonSet{},
			expect: "",
		},
		{
			name: "matchLabels preferred over metadata",
			ds: appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app.kubernetes.io/name": "metadata-name"},
				},
				Spec: appsv1.DaemonSetSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app.kubernetes.io/name": "selector-name"},
					},
				},
			},
			expect: "app.kubernetes.io/name=selector-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDCGMSelector(tt.ds)
			if got != tt.expect {
				t.Errorf("extractDCGMSelector() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestDiscoverDCGM(t *testing.T) {
	log := logging.New()
	ctx := context.Background()

	t.Run("finds dcgm in another namespace", func(t *testing.T) {
		k8sClient := fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "gpu-system"}},
			&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "dcgm-exporter",
					Namespace: "gpu-system",
					Labels:    map[string]string{"app.kubernetes.io/name": "dcgm-exporter"},
				},
				Spec: appsv1.DaemonSetSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app.kubernetes.io/name": "dcgm-exporter"},
					},
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Image: "nvcr.io/nvidia/k8s/dcgm-exporter:3.3.0"},
							},
						},
					},
				},
			},
		)

		result, err := discoverDCGM(ctx, log, k8sClient, "kvisor", "castai-agent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.DCGMExists {
			t.Error("expected DCGMExists=true")
		}
		if result.DCGMSelector != "app.kubernetes.io/name=dcgm-exporter" {
			t.Errorf("unexpected selector: %q", result.DCGMSelector)
		}
	})

	t.Run("skips self daemonset", func(t *testing.T) {
		k8sClient := fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "castai-agent"}},
			&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "kvisor",
					Namespace: "castai-agent",
				},
				Spec: appsv1.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Image: "nvcr.io/nvidia/k8s/dcgm-exporter:3.3.0"},
							},
						},
					},
				},
			},
		)

		result, err := discoverDCGM(ctx, log, k8sClient, "kvisor", "castai-agent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.DCGMExists {
			t.Error("expected DCGMExists=false (self DS should be skipped)")
		}
	})

	t.Run("nothing found", func(t *testing.T) {
		k8sClient := fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
			&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "fluentd", Namespace: "default"},
				Spec: appsv1.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Image: "fluentd:v1"}},
						},
					},
				},
			},
		)

		result, err := discoverDCGM(ctx, log, k8sClient, "kvisor", "castai-agent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.DCGMExists {
			t.Error("expected DCGMExists=false")
		}
	})
}

func TestWriteResult(t *testing.T) {
	log := logging.New()
	dir := t.TempDir()

	result := discoveryResult{DCGMExists: true, DCGMSelector: "app.kubernetes.io/name=dcgm-exporter"}
	if err := writeResult(log, dir, result); err != nil {
		t.Fatalf("writeResult failed: %v", err)
	}

	assertFileContent(t, filepath.Join(dir, "dcgm-exists"), "true")
	assertFileContent(t, filepath.Join(dir, "dcgm-selector"), "app.kubernetes.io/name=dcgm-exporter")
}

func TestWriteResultNotFound(t *testing.T) {
	log := logging.New()
	dir := t.TempDir()

	result := discoveryResult{DCGMExists: false}
	if err := writeResult(log, dir, result); err != nil {
		t.Fatalf("writeResult failed: %v", err)
	}

	assertFileContent(t, filepath.Join(dir, "dcgm-exists"), "false")
	assertFileContent(t, filepath.Join(dir, "dcgm-selector"), "")
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if got := string(b); got != want {
		t.Errorf("file %s = %q, want %q", path, got, want)
	}
}

func makeDSWithContainer(c corev1.Container) appsv1.DaemonSet {
	return appsv1.DaemonSet{
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{c},
				},
			},
		},
	}
}
