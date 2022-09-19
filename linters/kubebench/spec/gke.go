package spec

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func GKE(nodeName, jobName string) *batchv1.Job {
	//https://raw.githubusercontent.com/aquasecurity/kube-bench/v0.6.9/job-gke.yaml
	job := &batchv1.Job{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:   jobName,
			Labels: map[string]string{"app": "kube-bench"},
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					HostPID:       true,
					NodeName:      nodeName,
					RestartPolicy: "Never",
					Containers: []corev1.Container{
						{
							Name:  "kube-bench",
							Image: "docker.io/aquasec/kube-bench:v0.6.9",
							Command: []string{
								"kube-bench",
								"run",
								"--targets",
								"node,policies,managedservices",
								"--benchmark",
								"gke-1.2.0",
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
									Name:      "etc-kubernetes",
									MountPath: "/etc/kubernetes",
									ReadOnly:  true,
								},
								{
									Name:      "home-kubernetes",
									MountPath: "/home/kubernetes",
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
					},
				},
			},
		},
	}

	return job
}
