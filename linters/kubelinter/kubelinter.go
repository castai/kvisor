package kubelinter

import (
	"fmt"

	"github.com/samber/lo"
	"golang.stackrox.io/kube-linter/pkg/builtinchecks"
	"golang.stackrox.io/kube-linter/pkg/checkregistry"
	kubelinterconfig "golang.stackrox.io/kube-linter/pkg/config"
	"golang.stackrox.io/kube-linter/pkg/configresolver"
	"golang.stackrox.io/kube-linter/pkg/diagnostic"
	"golang.stackrox.io/kube-linter/pkg/ignore"
	"golang.stackrox.io/kube-linter/pkg/instantiatedcheck"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	"golang.stackrox.io/kube-linter/pkg/run"
	_ "golang.stackrox.io/kube-linter/pkg/templates/accesstoresources" // Import check templates.
	_ "golang.stackrox.io/kube-linter/pkg/templates/antiaffinity"
	_ "golang.stackrox.io/kube-linter/pkg/templates/clusteradminrolebinding"
	_ "golang.stackrox.io/kube-linter/pkg/templates/containercapabilities"
	_ "golang.stackrox.io/kube-linter/pkg/templates/cpurequirements"
	_ "golang.stackrox.io/kube-linter/pkg/templates/danglinghpa"
	_ "golang.stackrox.io/kube-linter/pkg/templates/danglingnetworkpolicy"
	_ "golang.stackrox.io/kube-linter/pkg/templates/danglingnetworkpolicypeer"
	_ "golang.stackrox.io/kube-linter/pkg/templates/danglingservice"
	_ "golang.stackrox.io/kube-linter/pkg/templates/deprecatedserviceaccount"
	_ "golang.stackrox.io/kube-linter/pkg/templates/disallowedgvk"
	_ "golang.stackrox.io/kube-linter/pkg/templates/envvar"
	_ "golang.stackrox.io/kube-linter/pkg/templates/forbiddenannotation"
	_ "golang.stackrox.io/kube-linter/pkg/templates/hostipc"
	_ "golang.stackrox.io/kube-linter/pkg/templates/hostmounts"
	_ "golang.stackrox.io/kube-linter/pkg/templates/hostnetwork"
	_ "golang.stackrox.io/kube-linter/pkg/templates/hostpid"
	_ "golang.stackrox.io/kube-linter/pkg/templates/hpareplicas"
	_ "golang.stackrox.io/kube-linter/pkg/templates/imagepullpolicy"
	_ "golang.stackrox.io/kube-linter/pkg/templates/latesttag"
	_ "golang.stackrox.io/kube-linter/pkg/templates/livenessprobe"
	_ "golang.stackrox.io/kube-linter/pkg/templates/memoryrequirements"
	_ "golang.stackrox.io/kube-linter/pkg/templates/mismatchingselector"
	_ "golang.stackrox.io/kube-linter/pkg/templates/namespace"
	_ "golang.stackrox.io/kube-linter/pkg/templates/nodeaffinity"
	_ "golang.stackrox.io/kube-linter/pkg/templates/nonexistentserviceaccount"
	_ "golang.stackrox.io/kube-linter/pkg/templates/nonisolatedpod"
	_ "golang.stackrox.io/kube-linter/pkg/templates/ports"
	_ "golang.stackrox.io/kube-linter/pkg/templates/privileged"
	_ "golang.stackrox.io/kube-linter/pkg/templates/privilegedports"
	_ "golang.stackrox.io/kube-linter/pkg/templates/privilegeescalation"
	_ "golang.stackrox.io/kube-linter/pkg/templates/readinessprobe"
	_ "golang.stackrox.io/kube-linter/pkg/templates/readonlyrootfs"
	_ "golang.stackrox.io/kube-linter/pkg/templates/readsecret"
	_ "golang.stackrox.io/kube-linter/pkg/templates/replicas"
	_ "golang.stackrox.io/kube-linter/pkg/templates/requiredannotation"
	_ "golang.stackrox.io/kube-linter/pkg/templates/requiredlabel"
	_ "golang.stackrox.io/kube-linter/pkg/templates/runasnonroot"
	_ "golang.stackrox.io/kube-linter/pkg/templates/serviceaccount"
	_ "golang.stackrox.io/kube-linter/pkg/templates/servicetype"
	_ "golang.stackrox.io/kube-linter/pkg/templates/sysctl"
	_ "golang.stackrox.io/kube-linter/pkg/templates/targetport"
	_ "golang.stackrox.io/kube-linter/pkg/templates/unsafeprocmount"
	_ "golang.stackrox.io/kube-linter/pkg/templates/updateconfig"
	_ "golang.stackrox.io/kube-linter/pkg/templates/wildcardinrules"
	_ "golang.stackrox.io/kube-linter/pkg/templates/writablehostmount"

	"github.com/castai/sec-agent/types"
)

func New(checks []string) *Linter {
	return &Linter{checks: checks}
}

type Linter struct {
	checks []string
}

func (l *Linter) Run(objects []lintcontext.Object) ([]LintCheck, error) {
	registry := checkregistry.New()

	if err := builtinchecks.LoadInto(registry); err != nil {
		return nil, fmt.Errorf("load info from registry: %w", err)
	}

	cfg := kubelinterconfig.Config{
		Checks: kubelinterconfig.ChecksConfig{
			AddAllBuiltIn: true,
		},
	}
	if err := configresolver.LoadCustomChecksInto(&cfg, registry); err != nil {
		return nil, fmt.Errorf("loading custom checks info: %w", err)
	}

	lintctx := &lintContext{
		objects: objects,
	}

	res, err := runKubeLinter([]lintcontext.LintContext{lintctx}, registry, l.checks)
	if err != nil {
		return nil, err
	}

	// For wow we group by objects and do not include multiple diagnostics, eg. pod with multiple containers.
	// Kubelinter can report issues on container level, but container name is included only as string in diagnostic message.
	checks := make(map[string]LintCheck)
	for _, check := range res.Reports {
		obj := check.Object.K8sObject

		kind := obj.GetObjectKind().GroupVersionKind()
		apiVersion := "v1"
		if kind.Group != "" {
			apiVersion = fmt.Sprintf("%s/%s", kind.Group, kind.Version)
		}

		resCheck := LintCheck{
			ID:      check.Check,
			Message: check.Diagnostic.Message,
			Failed:  check.Diagnostic.Message != "",
			Linter:  "kubelinter",
			Resource: types.Resource{
				ObjectMeta: types.ObjectMeta{
					Namespace: obj.GetNamespace(),
					Name:      obj.GetName(),
				},
				ObjectType: types.ObjectType{
					APIVersion: apiVersion,
					Kind:       kind.Kind,
				},
			},
		}
		checks[resCheck.ID+resCheck.ObjectKey()] = resCheck
	}
	return lo.Values(checks), nil
}

func runKubeLinter(lintCtxs []lintcontext.LintContext, registry checkregistry.CheckRegistry, checks []string) (run.Result, error) {
	var result run.Result

	instantiatedChecks := make([]*instantiatedcheck.InstantiatedCheck, 0, len(checks))
	for _, checkName := range checks {
		instantiatedCheck := registry.Load(checkName)
		if instantiatedCheck == nil {
			return run.Result{}, fmt.Errorf("check %q not found", checkName)
		}
		instantiatedChecks = append(instantiatedChecks, instantiatedCheck)
		result.Checks = append(result.Checks, instantiatedCheck.Spec)
	}

	for _, lintCtx := range lintCtxs {
		for _, obj := range lintCtx.Objects() {
			for _, check := range instantiatedChecks {
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

	return result, nil
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