package kubelinter

import (
	"fmt"

	"github.com/castai/kvisor/cmd/controller/state/kubelinter/customchecks/additionalcapabilities"
	"github.com/castai/kvisor/cmd/controller/state/kubelinter/customchecks/automount"
	"github.com/castai/kvisor/cmd/controller/state/kubelinter/customchecks/containerdsock"
	"github.com/castai/kvisor/cmd/controller/state/kubelinter/customchecks/networkpolicypernamespace"
	"github.com/castai/kvisor/cmd/controller/state/kubelinter/customchecks/securitycontext"
	"github.com/castai/kvisor/cmd/controller/state/kubelinter/customobjectkinds"
	"github.com/samber/lo"
	"golang.stackrox.io/kube-linter/pkg/builtinchecks"
	"golang.stackrox.io/kube-linter/pkg/checkregistry"
	"golang.stackrox.io/kube-linter/pkg/config"
	kubelinterconfig "golang.stackrox.io/kube-linter/pkg/config"
	"golang.stackrox.io/kube-linter/pkg/configresolver"
	"golang.stackrox.io/kube-linter/pkg/diagnostic"
	"golang.stackrox.io/kube-linter/pkg/ignore"
	"golang.stackrox.io/kube-linter/pkg/instantiatedcheck"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	"golang.stackrox.io/kube-linter/pkg/run"
	_ "golang.stackrox.io/kube-linter/pkg/templates/all"
	"k8s.io/apimachinery/pkg/types"
)

func New(checks []string) (*Linter, error) {
	registry := checkregistry.New()

	if err := builtinchecks.LoadInto(registry); err != nil {
		return nil, fmt.Errorf("load info from registry: %w", err)
	}

	registerCustomObjectKinds()

	if err := registerCustomChecks(registry); err != nil {
		return nil, fmt.Errorf("loading custom CAST check: %w", err)
	}

	cfg := kubelinterconfig.Config{
		Checks: kubelinterconfig.ChecksConfig{
			AddAllBuiltIn: true,
		},
	}
	if err := configresolver.LoadCustomChecksInto(&cfg, registry); err != nil {
		return nil, fmt.Errorf("loading custom checks info: %w", err)
	}

	rules := make(map[string]struct{})
	instantiatedChecks := make([]*instantiatedcheck.InstantiatedCheck, 0, len(checks))
	for _, checkName := range checks {
		rules[checkName] = struct{}{}
		instantiatedCheck := registry.Load(checkName)
		if instantiatedCheck == nil {
			return nil, fmt.Errorf("check %q not found", checkName)
		}
		if checkName == "namespace" {
			hideKubernetesDefaultService(instantiatedCheck)
		}
		instantiatedChecks = append(instantiatedChecks, instantiatedCheck)
	}

	return &Linter{
		rules:              rules,
		registry:           registry,
		instantiatedChecks: instantiatedChecks,
	}, nil
}

func registerCustomChecks(registry checkregistry.CheckRegistry) error {
	checks := []*config.Check{
		automount.Check(),
		containerdsock.Check(),
		securitycontext.Check(),
		networkpolicypernamespace.Check(),
		additionalcapabilities.Check(),
	}
	for _, check := range checks {
		if err := registry.Register(check); err != nil {
			return err
		}
	}
	return nil
}

func registerCustomObjectKinds() {
	customobjectkinds.RegisterNamespaceKind()
}

type Linter struct {
	rules              map[string]struct{}
	registry           checkregistry.CheckRegistry
	instantiatedChecks []*instantiatedcheck.InstantiatedCheck
}

func (l *Linter) RunWithRules(objects []lintcontext.Object, rules []string) ([]LinterCheck, error) {
	return l.run(objects, lo.SliceToMap(rules, func(item string) (string, struct{}) {
		return item, struct{}{}
	}))
}

func (l *Linter) Run(objects []lintcontext.Object) ([]LinterCheck, error) {
	return l.run(objects, l.rules)
}

func (l *Linter) run(objects []lintcontext.Object, rules map[string]struct{}) ([]LinterCheck, error) {
	lintctx := &lintContext{
		objects: objects,
	}

	res := l.runKubeLinter([]lintcontext.LintContext{lintctx}, rules)

	resources := make(map[types.UID]LinterCheck)
	for _, check := range res.Reports {
		obj := check.Object.K8sObject

		if _, ok := resources[obj.GetUID()]; !ok {
			resources[obj.GetUID()] = LinterCheck{
				ResourceID: string(obj.GetUID()),
				Failed:     new(LinterRuleSet),
				Passed:     new(LinterRuleSet),
			}
		}

		if check.Diagnostic.Message != "" {
			resources[obj.GetUID()].Failed.Add(LinterRuleMap[check.Check])
		} else {
			resources[obj.GetUID()].Passed.Add(LinterRuleMap[check.Check])
		}

	}

	return lo.Values(resources), nil
}

func (l *Linter) runKubeLinter(lintCtxs []lintcontext.LintContext, rules map[string]struct{}) run.Result {
	var result run.Result

	for _, instantiatedCheck := range l.instantiatedChecks {
		if _, ok := rules[instantiatedCheck.Spec.Name]; ok {
			result.Checks = append(result.Checks, instantiatedCheck.Spec)
		}
	}

	for _, lintCtx := range lintCtxs {
		for _, obj := range lintCtx.Objects() {
			for _, check := range l.instantiatedChecks {
				if _, ok := rules[check.Spec.Name]; !ok {
					continue
				}
				if !check.Matcher.Matches(obj.K8sObject.GetObjectKind().GroupVersionKind()) {
					continue
				}
				if ignore.ObjectForCheck(obj.K8sObject.GetAnnotations(), check.Spec.Name) {
					continue
				}
				diagnostics := check.Func(lintCtx, obj)
				if len(diagnostics) > 0 {
					for _, d := range diagnostics {
						result.Reports = append(result.Reports, diagnostic.WithContext{
							Diagnostic: d,
							Check:      check.Spec.Name,
							Object:     obj,
						})
					}
				} else {
					result.Reports = append(result.Reports, diagnostic.WithContext{
						Diagnostic: diagnostic.Diagnostic{},
						Check:      check.Spec.Name,
						Object:     obj,
					})
				}
			}
		}
	}

	return result
}

type lintContext struct {
	objects        []lintcontext.Object
	invalidObjects []lintcontext.InvalidObject
}

// Objects returns the (valid) objects loaded from this LintContext.
func (l *lintContext) Objects() []lintcontext.Object {
	return l.objects
}

// InvalidObjects returns any objects that we attempted to load, but which were invalid.
func (l *lintContext) InvalidObjects() []lintcontext.InvalidObject {
	return l.invalidObjects
}

func hideKubernetesDefaultService(check *instantiatedcheck.InstantiatedCheck) {
	check.Func = func(lintCtx lintcontext.LintContext, object lintcontext.Object) []diagnostic.Diagnostic {
		if object.K8sObject.GetNamespace() == "default" &&
			object.K8sObject.GetObjectKind().GroupVersionKind().Kind == "Service" &&
			object.K8sObject.GetName() == "kubernetes" {
			return []diagnostic.Diagnostic{}
		}
		return check.Func(lintCtx, object)
	}
}
