package spec

import (
	"github.com/samber/lo"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func AKS(nodeName, jobName string) *batchv1.Job {
	//https://raw.githubusercontent.com/aquasecurity/kube-bench/v0.6.9/job-aks.yaml
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: jobName,
			Annotations: map[string]string{
				"autoscaling.cast.ai/disposable": "true",
			},
			Labels: map[string]string{
				"app":                          "kube-bench",
				"app.kubernetes.io/managed-by": "castai",
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: lo.ToPtr(int32(0)),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					HostPID:                      true,
					NodeName:                     nodeName,
					RestartPolicy:                "Never",
					AutomountServiceAccountToken: lo.ToPtr(true),
					Containers: []corev1.Container{
						{
							Name:  "kube-bench",
							Image: "<placeholder>",
							SecurityContext: &corev1.SecurityContext{
								ReadOnlyRootFilesystem:   lo.ToPtr(true),
								AllowPrivilegeEscalation: lo.ToPtr(false),
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse(requestCPU),
									corev1.ResourceMemory: resource.MustParse(requestMem),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse(limitCPU),
									corev1.ResourceMemory: resource.MustParse(limitMem),
								},
							},
							Command: []string{
								"/usr/local/bin/kvisor-agent",
							},
							Args: []string{
								"kube-bench",
								"--config-dir", "/etc/kubebench-rules/",
								"run",
								"--targets", "node",
								"--benchmark", "aks-1.3",
								"--json",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "var-lib-kubelet",
									MountPath: "/var/lib/kubelet",
									ReadOnly:  true,
								},
								{
									Name:      "etc-systemd",
									MountPath: "/etc/systemd",
									ReadOnly:  true,
								},
								{
									Name:      "etc-default",
									MountPath: "/etc/default",
									ReadOnly:  true,
								},
								{
									Name:      "etc-kubernetes",
									MountPath: "/etc/kubernetes",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "var-lib-kubelet",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/kubelet",
								},
							},
						},
						{
							Name: "etc-systemd",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/systemd",
								},
							},
						},
						{
							Name: "etc-default",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/default",
								},
							},
						},
						{
							Name: "etc-kubernetes",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/kubernetes",
								},
							},
						},
					},
				},
			},
		},
	}
}
