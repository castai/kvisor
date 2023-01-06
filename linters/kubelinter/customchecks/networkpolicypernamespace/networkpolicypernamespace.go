package networkpolicypernamespace

import (
	"fmt"
	"strings"

	"golang.stackrox.io/kube-linter/pkg/check"
	"golang.stackrox.io/kube-linter/pkg/config"
	"golang.stackrox.io/kube-linter/pkg/diagnostic"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	"golang.stackrox.io/kube-linter/pkg/templates"
	"golang.stackrox.io/kube-linter/pkg/templates/util"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/castai/kvisor/linters/kubelinter/customobjectkinds"
)

func Check() *config.Check {
	return &config.Check{
		Name:        "network-policy-per-namespace",
		Description: "Use network policies to isolate traffic in your cluster network",
		Template:    "network-policy-per-namespace",
		Params:      map[string]interface{}{},
	}
}

func init() {
	networkPolicyGVR := networkingv1.SchemeGroupVersion.WithKind("NetworkPolicy")

	templates.Register(check.Template{
		HumanName: "Use network policies to isolate traffic in your cluster network",
		Key:       "network-policy-per-namespace",
		SupportedObjectKinds: config.ObjectKindsDesc{
			ObjectKinds: []string{customobjectkinds.Namespace},
		},
		Parameters:             ParamDescs,
		ParseAndValidateParams: ParseAndValidate,
		Instantiate: WrapInstantiateFunc(func(_ Params) (check.Func, error) {
			return func(ctx lintcontext.LintContext, object lintcontext.Object) []diagnostic.Diagnostic {
				ns, ok := object.K8sObject.(*corev1.Namespace)
				if !ok {
					return nil
				}
				for _, obj := range ctx.Objects() {
					if obj.GetK8sObjectName().GroupVersionKind == networkPolicyGVR && obj.K8sObject.GetNamespace() == ns.Name {
						return nil
					}
				}
				return []diagnostic.Diagnostic{{Message: "Namespace does not have any network policy"}}
			}, nil
		}),
	})
}

type Params struct {
}

var (
	// Use some imports in case they don't get used otherwise.
	_ = util.MustParseParameterDesc
	_ = fmt.Sprintf

	ParamDescs = []check.ParameterDesc{}
)

func (p *Params) Validate() error {
	var validationErrors []string
	if len(validationErrors) > 0 {
		return fmt.Errorf("invalid parameters: %s", strings.Join(validationErrors, ", "))
	}
	return nil
}

// ParseAndValidate instantiates a Params object out of the passed map[string]interface{},
// validates it, and returns it.
// The return type is interface{} to satisfy the type in the Template struct.
func ParseAndValidate(m map[string]interface{}) (interface{}, error) {
	var p Params
	if err := util.DecodeMapStructure(m, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// WrapInstantiateFunc is a convenience wrapper that wraps an untyped instantiate function
// into a typed one.
func WrapInstantiateFunc(f func(p Params) (check.Func, error)) func(interface{}) (check.Func, error) {
	return func(paramsInt interface{}) (check.Func, error) {
		return f(paramsInt.(Params))
	}
}
