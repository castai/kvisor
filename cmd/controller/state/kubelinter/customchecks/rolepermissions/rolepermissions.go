package rolepermissions

import (
	"fmt"
	"golang.stackrox.io/kube-linter/pkg/objectkinds"
	rbacv1 "k8s.io/api/rbac/v1"
	"slices"
	"strings"

	"golang.stackrox.io/kube-linter/pkg/check"
	"golang.stackrox.io/kube-linter/pkg/config"
	"golang.stackrox.io/kube-linter/pkg/diagnostic"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	"golang.stackrox.io/kube-linter/pkg/templates"
	"golang.stackrox.io/kube-linter/pkg/templates/util"
)

func Check() *config.Check {
	return &config.Check{
		Name:        "bind-impersonate-escalate",
		Description: "Use of Bind, Impersonate and Escalate permissions",
		Template:    "bind-impersonate-escalate",
		Params:      map[string]interface{}{},
	}
}

var (
	privescVerbs = []string{"bind", "escalate", "impersonate"}
)

func init() {
	templates.Register(check.Template{
		HumanName: "Use of Bind, Impersonate and Escalate permissions",
		Key:       "bind-impersonate-escalate",
		SupportedObjectKinds: config.ObjectKindsDesc{
			ObjectKinds: []string{
				objectkinds.Role,
				objectkinds.ClusterRole,
			},
		},
		Parameters:             ParamDescs,
		ParseAndValidateParams: ParseAndValidate,
		Instantiate: WrapInstantiateFunc(func(_ Params) (check.Func, error) {
			return func(_ lintcontext.LintContext, object lintcontext.Object) []diagnostic.Diagnostic {
				var policyRules []rbacv1.PolicyRule
				rb, ok := object.K8sObject.(*rbacv1.Role)
				if !ok {
					cr, ok := object.K8sObject.(*rbacv1.ClusterRole)
					if !ok {
						return nil
					}

					policyRules = cr.Rules
				}
				policyRules = rb.Rules

				for _, rule := range policyRules {
					for _, verb := range rule.Verbs {
						if slices.Contains(privescVerbs, verb) {
							return []diagnostic.Diagnostic{{Message: "Usage of 'bind, impersonate, escalate'"}}
						}
					}
				}

				return nil
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
