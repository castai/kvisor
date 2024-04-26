package app

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/samber/lo"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func newController(log *logging.Logger, client kubernetes.Interface) *controller {
	return &controller{
		log:    log.WithField("component", "ctrl"),
		client: client,
		rnd:    rand.New(rand.NewSource(time.Now().Unix())), //nolint:gosec
	}
}

type controller struct {
	client kubernetes.Interface
	log    *logging.Logger

	rnd *rand.Rand
}

func (c *controller) run(ctx context.Context) error {
	c.log.Info("running kvisor events generator")
	defer c.log.Info("stopping kvisor events generator")

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Minute):
				if err := c.removeRunnerContainer(ctx); err != nil {
					c.log.Errorf("remove runner container: %v", err)
				}
			}
		}
	}()

	for {
		rndDur := time.Duration(c.rnd.Intn(10)+1) * time.Minute
		c.log.Debugf("next inject after %s", rndDur)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(rndDur):
			if err := c.injectRunnerContainer(ctx); err != nil {
				c.log.Errorf("inject runner container: %v", err)
			}
		}
	}
}

func (c *controller) injectRunnerContainer(ctx context.Context) error {
	c.log.Debugf("running inject")
	dep, err := c.selectRandomDeployment(ctx)
	if err != nil {
		return err
	}
	c.log.Debugf("selected deployment, name=%s", dep.Name)

	if lo.ContainsBy(dep.Spec.Template.Spec.InitContainers, func(item corev1.Container) bool {
		return item.Name == "kvisor-anomaly-runner"
	}) {
		c.log.Debugf("skipping, deployment already contains event runner init container")
		return nil
	}

	imgName, err := c.getGeneratorImageName(ctx)
	if err != nil {
		return err
	}

	dep.Spec.Template.Spec.InitContainers = append(dep.Spec.Template.Spec.InitContainers, corev1.Container{
		Name:  "kvisor-anomaly-runner",
		Image: imgName,
		Args: []string{
			"-mode=event-runner",
		},
	})

	dep.ObjectMeta.Annotations["kvisor-anomaly-runner"] = "true"
	if _, err := c.client.AppsV1().Deployments(dep.Namespace).Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
		return err
	}

	c.log.Debugf("injected event runner init container")

	return nil
}

func (c *controller) removeRunnerContainer(ctx context.Context) error {
	c.log.Debugf("running cleanup")
	list, err := c.client.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, item := range list.Items {
		item := item
		if _, found := item.ObjectMeta.Annotations["kvisor-anomaly-runner"]; found {
			item.Spec.Template.Spec.InitContainers = lo.Filter(item.Spec.Template.Spec.InitContainers, func(item corev1.Container, index int) bool {
				return item.Name != "kvisor-anomaly-runner"
			})
			delete(item.ObjectMeta.Annotations, "kvisor-anomaly-runner")
			if _, err := c.client.AppsV1().Deployments(item.Namespace).Update(ctx, &item, metav1.UpdateOptions{}); err != nil {
				return err
			}
			c.log.Debugf("removed event runner init container from deployment, name=%s", item.Name)
		}
	}
	return nil
}

func (c *controller) selectRandomDeployment(ctx context.Context) (*appsv1.Deployment, error) {
	list, err := c.client.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	list.Items = lo.Filter(list.Items, func(item appsv1.Deployment, index int) bool {
		return item.Namespace != "kvisor"
	})

	if len(list.Items) == 0 {
		return nil, errors.New("no deployments")
	}

	di := c.rnd.Intn(len(list.Items))
	return &list.Items[di], nil
}

func (c *controller) getGeneratorImageName(ctx context.Context) (string, error) {
	dep, err := c.client.AppsV1().Deployments("kvisor").Get(ctx, "kvisor-event-generator", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return dep.Spec.Template.Spec.Containers[0].Image, nil
}
