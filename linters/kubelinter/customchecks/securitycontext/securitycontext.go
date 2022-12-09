package securitycontext

import (
	"fmt"
	"strings"

	"golang.stackrox.io/kube-linter/pkg/check"
	"golang.stackrox.io/kube-linter/pkg/config"
	"golang.stackrox.io/kube-linter/pkg/diagnostic"
	"golang.stackrox.io/kube-linter/pkg/extract"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	"golang.stackrox.io/kube-linter/pkg/objectkinds"
	"golang.stackrox.io/kube-linter/pkg/templates"
	"golang.stackrox.io/kube-linter/pkg/templates/util"
	corev1 "k8s.io/api/core/v1"
)

func Check() *config.Check {
	return &config.Check{
		Name:        "has-security-context",
		Description: "Resource has security context",
		Template:    "has-security-context",
		Params:      map[string]interface{}{},
	}
}

func init() {
	templates.Register(check.Template{
		HumanName: "Resource has security context",
		Key:       "has-security-context",
		SupportedObjectKinds: config.ObjectKindsDesc{
			ObjectKinds: []string{objectkinds.DeploymentLike},
		},
		Parameters:             ParamDescs,
		ParseAndValidateParams: ParseAndValidate,
		Instantiate: WrapInstantiateFunc(func(_ Params) (check.Func, error) {
			return func(_ lintcontext.LintContext, object lintcontext.Object) []diagnostic.Diagnostic {
				podSpec, found := extract.PodSpec(object.K8sObject)
				if !found {
					return nil
				}
				if isSecurityContextSet(podSpec.SecurityContext) {
					return nil
				}
				return []diagnostic.Diagnostic{{Message: "Resource does not have security context attached"}}
			}, nil
		}),
	})
}

func isSecurityContextSet(ctx *corev1.PodSecurityContext) bool {
	if ctx == nil {
		return false
	}
	return ctx.SELinuxOptions != nil || ctx.WindowsOptions != nil ||
		ctx.RunAsUser != nil || ctx.RunAsGroup != nil ||
		ctx.RunAsNonRoot != nil || ctx.SupplementalGroups != nil ||
		ctx.FSGroup != nil || ctx.Sysctls != nil ||
		ctx.FSGroupChangePolicy != nil || ctx.SeccompProfile != nil
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
