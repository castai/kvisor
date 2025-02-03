package bindings

import (
	"fmt"
	"golang.stackrox.io/kube-linter/pkg/templates"
	"slices"
	"strings"

	"golang.stackrox.io/kube-linter/pkg/check"
	"golang.stackrox.io/kube-linter/pkg/config"
	"golang.stackrox.io/kube-linter/pkg/diagnostic"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	"golang.stackrox.io/kube-linter/pkg/objectkinds"
	"golang.stackrox.io/kube-linter/pkg/templates/util"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	templateName = "bindings"
)

func Checks() []*config.Check {
	var checks []*config.Check
	for k, v := range rules {
		checks = append(checks, &config.Check{
			Name:        k,
			Template:    templateName,
			Description: v.Name,
			Params: map[string]interface{}{
				"Values":         v.Values,
				"ExcludedValues": v.ExcludedValues,
			},
		})
	}

	return checks
}

func init() {
	templates.Register(roleBindingsTemplate())
}

var (
	rules = map[string]BindingsCheck{
		"system-masters": {
			Name:   "Avoid use of system:masters group",
			Values: []string{"system:masters"},
		},
		"system-anonymous": {
			Name:   "Avoid binding to system:anonymous",
			Values: []string{"system:anonymous"},
		},
		"system-unauthenticated": {
			Name:           "Avoid non-default bindings to system:unauthenticated",
			Values:         []string{"system:unauthenticated"},
			ExcludedValues: []string{"system:public-info-viewer"},
		},
		"system-authenticated": {
			Name:           "Avoid non-default bindings to system:authenticated",
			Values:         []string{"system:authenticated"},
			ExcludedValues: []string{"system:public-info-viewer", "system:basic-user", "system:discovery"},
		},
	}
)

type BindingsCheck struct {
	Name           string
	Values         []string
	ExcludedValues []string
}

func roleBindingsTemplate() check.Template {
	template := check.Template{
		HumanName: "Avoid bindings to certain groups",
		Key:       templateName,
		SupportedObjectKinds: config.ObjectKindsDesc{
			ObjectKinds: []string{
				objectkinds.RoleBinding,
				objectkinds.ClusterRoleBinding,
			},
		},
		Parameters:             ParamDescs,
		ParseAndValidateParams: ParseAndValidate,
		Instantiate: WrapInstantiateFunc(func(p Params) (check.Func, error) {
			return func(_ lintcontext.LintContext, object lintcontext.Object) []diagnostic.Diagnostic {
				var subjects []rbacv1.Subject
				var roleRef rbacv1.RoleRef

				rb, ok := object.K8sObject.(*rbacv1.RoleBinding)
				if !ok {
					crb, ok := object.K8sObject.(*rbacv1.ClusterRoleBinding)
					if !ok {
						return nil
					}

					subjects = crb.Subjects
					roleRef = crb.RoleRef
				} else {
					subjects = rb.Subjects
					roleRef = rb.RoleRef
				}

				for _, subject := range subjects {
					if subject.Kind == "Group" && slices.Contains(p.Values, subject.Name) {
						if p.ExcludedValues == nil || !slices.Contains(p.ExcludedValues, roleRef.Name) {
							return []diagnostic.Diagnostic{{Message: fmt.Sprintf("Binding to %s", subject.Name)}}
						}
					}
				}

				return nil
			}, nil
		}),
	}

	return template
}

type Params struct {
	Values         []string
	ExcludedValues []string
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
