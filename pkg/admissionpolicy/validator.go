package admissionpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/policy/generic"
	"k8s.io/apiserver/pkg/admission/plugin/policy/matching"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

// Validator is a validating admission policy evaluator. It is a wrapper around
// validatingadmissionpolicy.CELPolicyEvaluator which runs an internal informer
// to keep the policy up to date.
type Validator struct {
	informers    informers.SharedInformerFactory
	plugin       validating.Plugin
	objectIfaces admission.ObjectInterfaces
}

// ValidationError is an error returned when a resource fails validation.
type ValidationError struct {
	Message string
	Reason  metav1.StatusReason
	Code    int32
	Causes  []metav1.StatusCause
}

// Error returns the error message.
func (e *ValidationError) Error() string {
	return e.Message
}

// NewEvaluator returns a new resource Validator that uses the given rest.Config to
// query policies from the API server. Run must be called to start the informaer cache.
func NewValidator(cfg *rest.Config) (*Validator, error) {
	scheme := runtime.NewScheme()
	err := clientgoscheme.AddToScheme(scheme)
	if err != nil {
		return nil, fmt.Errorf("adding client-go scheme to runtime scheme: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating clientset: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client: %w", err)
	}
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	restMapper := restmapper.NewDiscoveryRESTMapper([]*restmapper.APIGroupResources{})
	handler := admission.NewHandler(admission.Connect, admission.Create, admission.Delete, admission.Update)
	// Factories are called during ValidateInitialization
	plug := generic.NewPlugin(
		handler,
		func(f informers.SharedInformerFactory, _ kubernetes.Interface, di dynamic.Interface, rm meta.RESTMapper) generic.Source[validating.PolicyHook] {
			return generic.NewPolicySource(
				f.Admissionregistration().V1().ValidatingAdmissionPolicies().Informer(),
				f.Admissionregistration().V1().ValidatingAdmissionPolicyBindings().Informer(),
				validating.NewValidatingAdmissionPolicyAccessor,
				validating.NewValidatingAdmissionPolicyBindingAccessor,
				compilePolicy,
				f,
				di,
				rm,
			)
		},
		func(a authorizer.Authorizer, m *matching.Matcher) generic.Dispatcher[validating.PolicyHook] {
			return validating.NewDispatcher(a, generic.NewPolicyMatcher(m))
		},
	)
	plug.SetExternalKubeInformerFactory(informerFactory)
	plug.SetExternalKubeClientSet(client)
	plug.SetRESTMapper(restMapper)
	plug.SetDynamicClient(dynamicClient)
	plug.SetAuthorizer(&noopAuthorizer{})
	plug.SetEnabled(true)
	return &Validator{
		informers:    informerFactory,
		plugin:       validating.Plugin{Plugin: plug},
		objectIfaces: admission.NewObjectInterfacesFromScheme(scheme),
	}, nil
}

// Start starts the resource validator and syncs the informer cache. It does not
// block.
func (e *Validator) Start(stopCh <-chan struct{}) error {
	e.informers.Start(stopCh)
	e.plugin.SetDrainedNotification(stopCh)
	return e.plugin.ValidateInitialization()
}

// WaitForReady blocks until the informer cache is synced. Unfortunately, timeouts
// are not configurable currently and uses an internal value of 10 seconds.
func (e *Validator) WaitForReady() bool {
	return e.plugin.WaitForReady()
}

// Validate validates the given object against the policies and bindings in the cluster.
// The object is treated as if it is being created.
func (e *Validator) Validate(ctx context.Context, object runtime.Object) error {
	gvk := object.GetObjectKind().GroupVersionKind()
	kind := strings.ToLower(gvk.Kind) + "s"
	resource := gvk.GroupVersion().WithResource(kind)
	meta, ok := object.(metav1.Object)
	if !ok {
		return fmt.Errorf("object does not implement metav1.Object")
	}
	rec := admission.NewAttributesRecord(
		object,
		nil,
		gvk,
		meta.GetNamespace(),
		meta.GetName(),
		resource,
		"",
		admission.Create,
		&metav1.CreateOptions{},
		false,
		nil,
	)
	err := e.plugin.Validate(ctx, rec, e.objectIfaces)
	if err == nil {
		// Resource passed validation.
		return nil
	}
	var admissionError *kerrors.StatusError
	if errors.As(err, &admissionError) && (admissionError.ErrStatus.Reason == metav1.StatusReasonForbidden || admissionError.ErrStatus.Reason == metav1.StatusReasonInvalid) {
		// Resource failed validation
		return &ValidationError{
			Message: admissionError.ErrStatus.Message,
			Reason:  admissionError.ErrStatus.Reason,
			Code:    admissionError.ErrStatus.Code,
			Causes:  admissionError.ErrStatus.Details.Causes,
		}
	}
	// Some other error.
	return fmt.Errorf("validating object: %w", err)
}

type noopAuthorizer struct{}

func (n *noopAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	return authorizer.DecisionNoOpinion, "", nil
}
