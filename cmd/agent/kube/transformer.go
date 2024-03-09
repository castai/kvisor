package kube

import (
	"errors"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

func transformObject(obj kubernetesObject) {
	obj.SetManagedFields(nil)
	obj.SetAnnotations(nil)
	obj.SetLabels(nil)

	appsV1 := "apps/v1"
	v1 := "v1"
	switch o := obj.(type) {
	case *appsv1.ReplicaSet:
		o.Kind = "ReplicaSet"
		o.APIVersion = appsV1
		o.Spec = appsv1.ReplicaSetSpec{}
		o.Status = appsv1.ReplicaSetStatus{}
	case *corev1.Pod:
		o.Kind = "Pod"
		o.APIVersion = v1
		o.Spec = corev1.PodSpec{}
		o.Status = corev1.PodStatus{}
	case *batchv1.Job:
		o.Kind = "Job"
		o.APIVersion = "batch/v1"
		o.Spec = batchv1.JobSpec{}
		o.Status = batchv1.JobStatus{}
	case *batchv1.CronJob:
		o.Kind = "CronJob"
		o.APIVersion = "batch/v1"
		o.Spec = batchv1.CronJobSpec{}
		o.Status = batchv1.CronJobStatus{}
	}
}

func informerTransformer(i any) (any, error) {
	obj, ok := i.(kubernetesObject)
	if !ok {
		return nil, errors.New("unsupported object")
	}

	transformObject(obj)

	return obj, nil
}
