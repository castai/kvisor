package nodecomponentscollector

import (
	"github.com/samber/lo"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	limitCPU   = "200m"
	limitMem   = "128Mi"
	requestCPU = "10m"
	requestMem = "64Mi"
)

func generateJobSpec(nodeId, nodeName, jobName, serviceAccountName string) *batchv1.Job {
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: jobName,
			Annotations: map[string]string{
				"autoscaling.cast.ai/disposable": "true",
			},
			Labels: map[string]string{
				"app":                          "node-components-collector",
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
					ServiceAccountName:           serviceAccountName,
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
								"/usr/local/bin/kvisor-collector",
							},
							Args: []string{
								"run",
							},
							Env: []corev1.EnvVar{
								{
									Name:  "NODE_ID",
									Value: nodeId,
								},
								{
									Name:  "NODE_NAME",
									Value: nodeName,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "etc-kubernetes",
									MountPath: "/etc/kubernetes",
									ReadOnly:  true,
								},
								{
									Name:      "home-kubernetes",
									MountPath: "/home/kubernetes",
									ReadOnly:  true,
								},
								{
									Name:      "var-lib-kubelet",
									MountPath: "/var/lib/kubelet",
									ReadOnly:  true,
								},
								{
									Name:      "etc-default-kubelet",
									MountPath: "/etc/default/kubelet",
									ReadOnly:  true,
								},
								{
									Name:      "var-snap-kubelet",
									MountPath: "/var/snap/kubelet/",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "etc-kubernetes",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/kubernetes",
								},
							},
						},
						{
							Name: "home-kubernetes",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/home/kubernetes",
								},
							},
						},
						{
							Name: "var-lib-kubelet",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/kubelet",
								},
							},
						},
						{
							Name: "etc-default-kubelet",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/default/kubelet",
								},
							},
						},
						{
							Name: "var-snap-kubelet",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/snap/kubelet",
								},
							},
						},
					},
				},
			},
		},
	}
}
