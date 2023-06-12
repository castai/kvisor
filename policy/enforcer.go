package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"golang.stackrox.io/kube-linter/pkg/k8sutil"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/castai/telemetry"
	"github.com/castai/kvisor/linters/kubelinter"
)

type Enforcer interface {
	TelemetryObserver() telemetry.Observer
	admission.Handler
}

type enforcer struct {
	objectFilters []objectFilter
	linter        *kubelinter.Linter
	enforcedRules []string
	mutex         sync.RWMutex
}

func NewEnforcer(linter *kubelinter.Linter) Enforcer {
	return &enforcer{
		objectFilters: []objectFilter{
			skipObjectsWithOwners,
		},
		linter: linter,
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

func (e *enforcer) Handle(ctx context.Context, request admission.Request) admission.Response {
	enforcedRules := e.rules()
	if len(enforcedRules) == 0 {
		return admission.Allowed("no enforced rules")
	}

	// Unmarshal object.
	var object k8sutil.Object
	kind := request.Kind.Kind

	switch kind {
	case "Pod":
		var pod *corev1.Pod
		if err := json.Unmarshal(request.Object.Raw, &pod); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}

		object = pod
	case "Deployment":
		var deployment *appsv1.Deployment
		if err := json.Unmarshal(request.Object.Raw, &deployment); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = deployment
	case "ReplicaSet":
		var replicaSet *appsv1.ReplicaSet
		if err := json.Unmarshal(request.Object.Raw, &replicaSet); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = replicaSet
	case "StatefulSet":
		var statefulSet *appsv1.StatefulSet
		if err := json.Unmarshal(request.Object.Raw, &statefulSet); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = statefulSet
	case "CronJob":
		var cronJob *batchv1.CronJob
		if err := json.Unmarshal(request.Object.Raw, &cronJob); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = cronJob
	case "Job":
		var job *batchv1.Job
		if err := json.Unmarshal(request.Object.Raw, &job); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = job
	case "Role":
		var role *rbacv1.Role
		if err := json.Unmarshal(request.Object.Raw, &role); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = role
	case "ClusterRole":
		var clusterRole *rbacv1.ClusterRole
		if err := json.Unmarshal(request.Object.Raw, &clusterRole); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = clusterRole
	case "RoleBinding":
		var roleBinding *rbacv1.RoleBinding
		if err := json.Unmarshal(request.Object.Raw, &roleBinding); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = roleBinding
	case "ClusterRoleBinding":
		var clusterRoleBinding *rbacv1.ClusterRoleBinding
		if err := json.Unmarshal(request.Object.Raw, &clusterRoleBinding); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = clusterRoleBinding
	case "NetworkPolicy":
		var networkPolicy *networkingv1.NetworkPolicy
		if err := json.Unmarshal(request.Object.Raw, &networkPolicy); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = networkPolicy
	case "Ingress":
		var ingress *networkingv1.Ingress
		if err := json.Unmarshal(request.Object.Raw, &ingress); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = ingress
	case "Namespace":
		var namespace *corev1.Namespace
		if err := json.Unmarshal(request.Object.Raw, &namespace); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = namespace
	case "Service":
		var service *corev1.Service
		if err := json.Unmarshal(request.Object.Raw, &service); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		object = service
	}

	if object == nil {
		return admission.Allowed(fmt.Sprintf("kind %q not linted", kind))
	}

	for i := range e.objectFilters {
		if skip, msg := e.objectFilters[i](object); skip {
			return admission.Allowed(msg)
		}
	}

	// Run linter.
	checks, err := e.linter.RunWithRules(
		[]lintcontext.Object{
			{
				Metadata: lintcontext.ObjectMetadata{
					FilePath: "none",
				},
				K8sObject: object,
			},
		},
		enforcedRules,
	)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	if len(checks) != 1 {
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("unexpected checks len %d", len(checks)))
	}

	rules := checks[0].Failed.Rules()
	if len(rules) == 0 {
		return admission.Allowed(fmt.Sprintf("object of kind %q passed all checks", kind))
	}

	sort.Strings(rules)
	return admission.Denied(fmt.Sprintf("%s did not pass these checks: %v", kind, rules))
}

func (e *enforcer) rules() []string {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.enforcedRules
}
