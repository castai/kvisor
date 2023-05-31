package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/linters/kubelinter"
	"github.com/samber/lo"
	"golang.stackrox.io/kube-linter/pkg/k8sutil"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	v1 "k8s.io/apiserver/pkg/apis/example/v1"
)

type Enforcer interface {
	admission.Handler
}

type enforcer struct {
	objectFilters []objectFilter
	linter        *kubelinter.Linter
}

func NewEnforcer(linter *kubelinter.Linter) Enforcer {
	return &enforcer{
		objectFilters: []objectFilter{
			skipObjectsWithOwners,
		},
		linter: linter,
	}
}

func (e *enforcer) Handle(ctx context.Context, request admission.Request) admission.Response {
	// Unmarshal object.
	var object k8sutil.Object
	kind := request.Kind.Kind

	switch kind {
	case "Pod":
		var pod *v1.Pod
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
		e.rules(),
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
	// TODO: this should be dynamic.
	return lo.Keys(castai.LinterRuleMap)
}
