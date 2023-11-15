package spec

import (
	"github.com/samber/lo"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Master(nodeName, jobName string) *batchv1.Job {
	//https://raw.githubusercontent.com/aquasecurity/kube-bench/v0.6.9/job-master.yaml
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: jobName,
			Labels: map[string]string{
				"app":                          "kube-bench",
				"app.kubernetes.io/managed-by": "castai",
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: lo.ToPtr(int32(0)),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					HostPID: true,
					// https://github.com/cloudnativelabs/kube-router/blob/master/daemonset/kube-router-proxy-daemonset.yaml#L102
					Tolerations: []corev1.Toleration{
						{
							Effect:   "NoSchedule",
							Operator: "Exists",
						},
						{
							Key:      "CriticalAddonsOnly",
							Operator: "Exists",
						},
						{
							Effect:   "NoExecute",
							Operator: "Exists",
						},
					},
					NodeName:                     nodeName,
					RestartPolicy:                "Never",
					AutomountServiceAccountToken: lo.ToPtr(true),
					Containers: []corev1.Container{
						{
							Name:  "kube-bench",
							Image: kubeBenchImage,
							SecurityContext: &corev1.SecurityContext{
								ReadOnlyRootFilesystem:   lo.ToPtr(true),
								AllowPrivilegeEscalation: lo.ToPtr(false),
							},
							Command: []string{
								"kube-bench", "run", "--targets", "master", "--json",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "var-lib-etcd",
									MountPath: "/var/lib/etcd",
									ReadOnly:  true,
								},
								{
									Name:      "var-lib-kubelet",
									MountPath: "/var/lib/kubelet",
									ReadOnly:  true,
								},
								{
									Name:      "var-lib-kube-scheduler",
									MountPath: "/var/lib/kube-scheduler",
									ReadOnly:  true,
								},
								{
									Name:      "var-lib-kube-controller-manager",
									MountPath: "/var/lib/kube-controller-manager",
									ReadOnly:  true,
								},
								{
									Name:      "etc-systemd",
									MountPath: "/etc/systemd",
									ReadOnly:  true,
								},
								{
									Name:      "lib-systemd",
									MountPath: "/lib/systemd/",
									ReadOnly:  true,
								},
								{
									Name:      "srv-kubernetes",
									MountPath: "/srv/kubernetes/",
									ReadOnly:  true,
								},
								{
									Name:      "etc-kubernetes",
									MountPath: "/etc/kubernetes",
									ReadOnly:  true,
								},
								// /usr/local/mount-from-host/bin is mounted to access kubectl / kubelet, for auto-detecting the Kubernetes version.
								// You can omit this mount if you specify --version as part of the command.
								{
									Name:      "usr-bin",
									MountPath: "/usr/local/mount-from-host/bin",
									ReadOnly:  true,
								},
								{
									Name:      "etc-cni-netd",
									MountPath: "/etc/cni/net.d/",
									ReadOnly:  true,
								},
								{
									Name:      "opt-cni-bin",
									MountPath: "/opt/cni/bin/",
									ReadOnly:  true,
								},
								{
									Name:      "etc-passwd",
									MountPath: "/etc/passwd",
									ReadOnly:  true,
								},
								{
									Name:      "etc-group",
									MountPath: "/etc/group",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "var-lib-etcd",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/etcd",
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
							Name: "var-lib-kube-scheduler",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/kube-scheduler",
								},
							},
						},
						{
							Name: "var-lib-kube-controller-manager",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/kube-controller-manager",
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
							Name: "lib-systemd",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/lib/systemd",
								},
							},
						},
						{
							Name: "srv-kubernetes",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/srv/kubernetes",
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
						{
							Name: "usr-bin",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/usr/bin",
								},
							},
						},
						{
							Name: "etc-cni-netd",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/cni/net.d/",
								},
							},
						},
						{
							Name: "opt-cni-bin",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/opt/cni/bin/",
								},
							},
						},
						{
							Name: "etc-passwd",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/passwd",
								},
							},
						},
						{
							Name: "etc-group",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/group",
								},
							},
						},
					},
				},
			},
		},
	}
}
