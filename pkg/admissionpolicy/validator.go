package admissionpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/validatingadmissionpolicy"
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
	ctrl         validatingadmissionpolicy.CELPolicyEvaluator
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
	dynamic, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client: %w", err)
	}
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	restMapper := restmapper.NewDiscoveryRESTMapper([]*restmapper.APIGroupResources{})
	controller := validatingadmissionpolicy.NewAdmissionController(
		informerFactory,
		client,
		restMapper,
		dynamic,
		&allowAllAuthorizer{},
	)
	err = controller.ValidateInitialization()
	if err != nil {
		return nil, fmt.Errorf("validating admission policy controller initialization: %w", err)
	}
	return &Validator{
		informers:    informerFactory,
		ctrl:         controller,
		objectIfaces: admission.NewObjectInterfacesFromScheme(scheme),
	}, nil
}

// Run starts the resource validator and syncs the informer cache. It blocks until
// the stopCh is closed. Calls to Validate will block until the informer cache
// is synced.
func (e *Validator) Run(stopCh <-chan struct{}) {
	e.informers.Start(stopCh)
	e.ctrl.Run(stopCh)
}

// HasSynced returns true if the resource evaluator's informer cache has synced.
func (e *Validator) HasSynced() bool {
	return e.ctrl.HasSynced()
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
	err := e.ctrl.Validate(ctx, rec, e.objectIfaces)
	if err == nil {
		// Resource passed validation.
		return nil
	}
	var admissionError *kerrors.StatusError
	if errors.As(err, &admissionError) && admissionError.ErrStatus.Reason == metav1.StatusReasonInvalid {
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

// allowAllAuthorizer is an authorizer that allows all requests. It is used to
// bypass the authorization checks for the policy evaluator.
type allowAllAuthorizer struct{}

// Authorize returns no opinion for all requests.
func (a *allowAllAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	return authorizer.DecisionNoOpinion, "", nil
}
