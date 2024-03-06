package kube

import (
	"errors"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// addObjectMeta adds missing metadata since kubernetes client removes object kind and api version information.
func addObjectMeta(o kubernetesObject) {
	appsV1 := "apps/v1"
	v1 := "v1"
	switch o := o.(type) {
	case *appsv1.ReplicaSet:
		o.Kind = "ReplicaSet"
		o.APIVersion = appsV1
	case *corev1.Pod:
		o.Kind = "Pod"
		o.APIVersion = v1
	case *batchv1.Job:
		o.Kind = "Job"
		o.APIVersion = "batch/v1"
	case *batchv1.CronJob:
		o.Kind = "CronJob"
		o.APIVersion = "batch/v1"
	}
}

func informerTransformer(i any) (any, error) {
	obj, ok := i.(kubernetesObject)
	if !ok {
		return nil, errors.New("unsupported object")
	}

	// Add missing metadata which is removed by k8s.
	addObjectMeta(obj)
	// Remove managed fields since we don't need them. This should decrease memory usage.
	obj.SetManagedFields(nil)

	return obj, nil
}
