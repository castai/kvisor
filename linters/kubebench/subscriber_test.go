package kubebench

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSubscriber(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	t.Run("creates jobs", func(t *testing.T) {
		r := require.New(t)
		ctx := context.Background()
		clientset := fake.NewSimpleClientset()
		subscriber := &Subscriber{
			log:      log,
			client:   clientset,
			delta:    newDeltaState(),
			provider: "gke",
		}

		err := subscriber.lintNode(ctx,
			&corev1.Node{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test_node",
				},
			},
		)
		// fake clientset doesn't create pod for job
		r.Errorf(err, "pod-not-found")

		_, err = clientset.BatchV1().Jobs(castAINamespace).Get(ctx, "kube-bench-node-test_node", metav1.GetOptions{})
		r.NoError(err)
	})

	t.Run("works only with nodes", func(t *testing.T) {
		r := require.New(t)
		subscriber := &Subscriber{
			log:      log,
			client:   nil,
			delta:    newDeltaState(),
			provider: "gke",
		}

		node := &corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "test_node",
			},
		}

		pod := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "test_pod",
			},
		}

		subscriber.OnAdd(node)
		subscriber.OnAdd(pod)

		r.Len(subscriber.delta.objectMap, 1)
	})
}
