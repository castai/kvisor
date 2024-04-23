package kube

import (
	"context"
	"testing"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFindWorkload(t *testing.T) {
	nodeName := "node-1"

	deploymentUID := types.UID("deployment-uid")
	deploymentName := "deployment-1"
	deploymentKind := "Deployment"

	daemonsetUID := types.UID("random-uid")
	daemonsetName := "random-1"
	daemonsetKind := "DaemonSet"

	replicasetUID := types.UID("replicaset-uid")
	replicasetName := "replicaset-1"
	replicasetKind := "ReplicaSet"

	statefulsetUID := types.UID("random-uid")
	statefulsetName := "random-1"
	statefulsetKind := "StatefulSet"

	podUID := types.UID("pod-uid")
	sentinelPodUID := types.UID("sentinel-pod-uid")
	podKind := "Pod"

	// This pod is used as a marker to know when all informer events have been processed.
	sentinelPod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1.SchemeGroupVersion.String(),
			Kind:       podKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "sentinel-pod-1",
			Namespace:   "default",
			UID:         sentinelPodUID,
			Labels:      map[string]string{},
			Annotations: map[string]string{},
		},
	}

	type testCase struct {
		title             string
		kubernetesObjects []kubernetesObject
		uidToSearch       types.UID
		expectedWorkload  Workload
		expectedError     error
	}

	testCases := []testCase{
		{
			title:       "get workload for pod with replicaset from deployment",
			uidToSearch: podUID,
			kubernetesObjects: []kubernetesObject{
				&appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:        replicasetName,
						Namespace:   "default",
						UID:         replicasetUID,
						Labels:      map[string]string{},
						Annotations: map[string]string{},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: appsv1.SchemeGroupVersion.String(),
								Kind:       deploymentKind,
								Name:       deploymentName,
								UID:        deploymentUID,
							},
						},
					},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "pod-1",
						Namespace:   "default",
						UID:         podUID,
						Labels:      map[string]string{},
						Annotations: map[string]string{},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: appsv1.SchemeGroupVersion.String(),
								Kind:       replicasetKind,
								Name:       replicasetName,
								UID:        replicasetUID,
							},
						},
					},
				},
			},
			expectedWorkload: Workload{
				UID:        deploymentUID,
				apiVersion: appsv1.SchemeGroupVersion.String(),
				kind:       deploymentKind,
				Name:       deploymentName,
			},
		},
		{
			title:       "get workload for pod in stateful set",
			uidToSearch: podUID,
			kubernetesObjects: []kubernetesObject{
				&appsv1.StatefulSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: appsv1.SchemeGroupVersion.String(),
						Kind:       statefulsetKind,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:        statefulsetName,
						Namespace:   "default",
						UID:         statefulsetUID,
						Labels:      map[string]string{},
						Annotations: map[string]string{},
					},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "pod-1",
						Namespace:   "default",
						UID:         podUID,
						Labels:      map[string]string{},
						Annotations: map[string]string{},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: appsv1.SchemeGroupVersion.String(),
								Kind:       statefulsetKind,
								Name:       statefulsetName,
								UID:        statefulsetUID,
							},
						},
					},
				},
			},
			expectedWorkload: Workload{
				apiVersion: appsv1.SchemeGroupVersion.String(),
				kind:       statefulsetKind,
				UID:        statefulsetUID,
				Name:       statefulsetName,
			},
		},
		{
			title:       "get workload for pod in daemon set",
			uidToSearch: podUID,
			kubernetesObjects: []kubernetesObject{
				&appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: appsv1.SchemeGroupVersion.String(),
						Kind:       daemonsetKind,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:        daemonsetName,
						Namespace:   "default",
						UID:         daemonsetUID,
						Labels:      map[string]string{},
						Annotations: map[string]string{},
					},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "pod-1",
						Namespace:   "default",
						UID:         podUID,
						Labels:      map[string]string{},
						Annotations: map[string]string{},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: appsv1.SchemeGroupVersion.String(),
								Kind:       daemonsetKind,
								Name:       daemonsetName,
								UID:        daemonsetUID,
							},
						},
					},
				},
			},
			expectedWorkload: Workload{
				apiVersion: appsv1.SchemeGroupVersion.String(),
				kind:       daemonsetKind,
				Name:       daemonsetName,
				UID:        daemonsetUID,
			},
		},
		{
			title: "get workload for standalone pod, should be error",
			kubernetesObjects: []kubernetesObject{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pod-1",
						Namespace:       "default",
						UID:             podUID,
						Labels:          map[string]string{},
						Annotations:     map[string]string{},
						OwnerReferences: []metav1.OwnerReference{},
					},
				},
			},
			uidToSearch:   podUID,
			expectedError: ErrNoWorkloadFound,
		},
	}

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			kubeObjects := make([]runtime.Object, 0, len(test.kubernetesObjects))

			for _, ko := range test.kubernetesObjects {
				kubeObjects = append(kubeObjects, ko)
			}

			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			fakeClient := fake.NewSimpleClientset(kubeObjects...)
			client := NewClient(logging.New(&logging.Config{}), fakeClient, nodeName)
			client.startInformers(ctx)

			// We create a sentinel pod to know when all informers are done processing.
			_, err := fakeClient.CoreV1().Pods("default").Create(ctx, sentinelPod, metav1.CreateOptions{})
			r.NoError(err)

			r.Eventually(func() bool {
				client.mu.RLock()
				defer client.mu.RUnlock()

				_, found := client.objects[sentinelPodUID]
				return found
			}, 2*time.Second, 100*time.Millisecond)

			w, err := client.findWorkload(test.uidToSearch)
			if test.expectedError != nil {
				r.Error(err)
				r.ErrorIs(err, test.expectedError)
			} else {
				r.NoError(err)
				r.Equal(test.expectedWorkload.apiVersion, w.apiVersion)
				r.Equal(test.expectedWorkload.kind, w.kind)
				r.Equal(test.expectedWorkload.UID, w.UID)
				r.Equal(test.expectedWorkload.Name, w.Name)
			}
		})
	}
}
