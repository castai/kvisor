package policy

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/castai/telemetry"
	"github.com/castai/kvisor/config"
)

type Enforcer interface {
	manager.Runnable
	TelemetryObserver() telemetry.Observer
}

type enforcer struct {
	serviceName       string
	objectFilters     []objectFilter
	kubeclient        kubernetes.Interface
	supportedPolicies []admissionregistrationv1beta1.ValidatingAdmissionPolicy
	enforcedRules     []string
	bundleRules       []string
	mutex             sync.RWMutex
	cfg               *config.PolicyEnforcement
	logger            logrus.FieldLogger
}

func NewEnforcer(
	kubeclient kubernetes.Interface, logger logrus.FieldLogger, serviceName string,
	cfg config.PolicyEnforcement,
) Enforcer {
	rules := map[string]struct{}{}
	for _, bundle := range cfg.Bundles {
		var ruleMap map[string]castai.LinterRule
		switch bundle {
		case "host-isolation":
			ruleMap = castai.HostIsolationBundle
		case "good-practices":
			ruleMap = castai.GoodPracticesBundle
		case "ports":
			ruleMap = castai.PortsBundle
		case "mount-points":
			ruleMap = castai.MountPointsBundle
		case "dangling-resources":
			ruleMap = castai.DanglingResourcesBundle
		case "rbac":
			ruleMap = castai.RBACBundle
		}
		for key := range ruleMap {
			rules[key] = struct{}{}
		}
	}

	return &enforcer{
		serviceName: serviceName,
		objectFilters: []objectFilter{
			skipObjectsWithOwners,
		},
		kubeclient:  kubeclient,
		bundleRules: lo.Keys(rules),
		cfg:         &cfg,
		logger:      logger,
	}
}

func (e *enforcer) Start(ctx context.Context) error {
	syncTicker := time.NewTicker(5 * time.Second)
	defer syncTicker.Stop()

	policies, err := loadPolicies()
	if err != nil {
		return fmt.Errorf("loading embedded policies: %w", err)
	}
	e.supportedPolicies = policies

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-syncTicker.C:
			e.logger.Infof("syncing admission policies")

			if err := e.syncPolicies(ctx); err != nil {
				log.Printf("error syncing policies: %v", err)
			}

			if err := e.syncBindings(ctx); err != nil {
				log.Printf("error syncing policy bindings: %v", err)
			}

			e.logger.Infof("syncing done")
		}
	}
}

func (e *enforcer) TelemetryObserver() telemetry.Observer {
	return func(r *castai.TelemetryResponse) {
		e.mutex.Lock()
		defer e.mutex.Unlock()
		e.enforcedRules = make([]string, 0, len(r.EnforcedRules))
		e.enforcedRules = append(e.enforcedRules, r.EnforcedRules...)
	}
}

func (e *enforcer) syncPolicies(ctx context.Context) error {
	vaps := e.kubeclient.AdmissionregistrationV1beta1().ValidatingAdmissionPolicies()

	list, err := vaps.List(ctx, metav1.ListOptions{
		LabelSelector: "cast.ai/instance=" + e.serviceName,
	})

	if err != nil {
		return fmt.Errorf("listing existing polices: %w", err)
	}

	existingPolicies := lo.SliceToMap(list.Items, func(policy admissionregistrationv1beta1.ValidatingAdmissionPolicy) (string, admissionregistrationv1beta1.ValidatingAdmissionPolicy) {
		return policy.Name, policy
	})

	supportedPolicies := lo.SliceToMap(e.supportedPolicies, func(policy admissionregistrationv1beta1.ValidatingAdmissionPolicy) (string, admissionregistrationv1beta1.ValidatingAdmissionPolicy) {
		return policy.Name, policy
	})

	toDelete, toCreate := lo.Difference(lo.Keys(existingPolicies), lo.Keys(supportedPolicies))

	for _, policyToDelete := range toDelete {
		if err := vaps.Delete(ctx, policyToDelete, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("deleting unused policy %s: %w", policyToDelete, err)
		}
	}

	for _, policyToCreate := range toCreate {
		policy := supportedPolicies[policyToCreate]
		policy.Labels["cast.ai/instance"] = e.serviceName

		_, err := vaps.Create(ctx, &policy, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating new policy %s: %w", policyToCreate, err)
		}
	}

	return nil
}

func (e *enforcer) syncBindings(ctx context.Context) error {
	vapbs := e.kubeclient.AdmissionregistrationV1beta1().ValidatingAdmissionPolicyBindings()

	list, err := vapbs.List(ctx, metav1.ListOptions{
		LabelSelector: "cast.ai/instance=" + e.serviceName,
	})

	if err != nil {
		return fmt.Errorf("listing existing policy bindings: %w", err)
	}

	existingBindings := lo.Map(list.Items, func(binding admissionregistrationv1beta1.ValidatingAdmissionPolicyBinding, i int) string {
		return binding.Name
	})

	needBindings := lo.Map(e.rules(), func(name string, i int) string {
		return name + ".policies.cast.ai"
	})

	e.logger.Debugf("enabled admission rules: %v", needBindings)

	toDelete, toCreate := lo.Difference(existingBindings, needBindings)

	for _, bindingToDelete := range toDelete {
		if err := vapbs.Delete(ctx, bindingToDelete, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("deleting unused policy binding %s: %w", bindingToDelete, err)
		}
	}

	for _, bindingToCreate := range toCreate {
		binding := admissionregistrationv1beta1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   bindingToCreate,
				Labels: map[string]string{"cast.ai/instance": e.serviceName},
			},
			Spec: admissionregistrationv1beta1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: bindingToCreate,
				ValidationActions: []admissionregistrationv1beta1.ValidationAction{
					admissionregistrationv1beta1.Deny, admissionregistrationv1beta1.Audit,
				},
			},
		}

		_, err := vapbs.Create(ctx, &binding, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating new policy binding %s: %w", bindingToCreate, err)
		}
	}

	return nil
}

func (e *enforcer) rules() []string {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return lo.Uniq(append(e.enforcedRules, e.bundleRules...))
}
