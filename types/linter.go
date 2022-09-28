package types

import "fmt"

type LinterRule int
type LinterRuleSet LinterRule

const (
	DanglingService LinterRule = 1 << iota
	DeprecatedServiceAccountField
	DokerSock
	DropNetRawCapability
	EnvVarSecret
	ExposedService
	HostIPC
	HostNetwork
	HostPID
	InvalidTargetPorta
	LatestTag
	MismatchingSelector
	NoAntiAffinity
	NoLivenessProbe
	NoReadOnlyRootFS
	NoReadinessProe
	NoRollingUpdateStrategy
	PrivilegeEsxalationContainer
	PrivilegedContainer
	PrivilegedProts
	RunAsNonRoot
	SensitiveHostMounts
	SSHPort
	UnsafeProcMount
	UnsafeSysctls
	UnsetMempryRequirements
	UseNamespace
	WritableHostMount
	ClusterAdminRoleBinding
	AccessToSecrets
	DefaultServiceAccount
	WildcardInRules
	AccessToCreatePods
	TokenAutomount
)

var LinterRuleMap = map[string]LinterRule{
	"dangling-service":                 DanglingService,
	"deprecated-service-account-field": DeprecatedServiceAccountField,
	"docker-sock":                      DokerSock,
	"drop-net-raw-capability":          DropNetRawCapability,
	"env-var-secret":                   EnvVarSecret,
	"exposed-services":                 ExposedService,
	"host-ipc":                         HostIPC,
	"host-network":                     HostNetwork,
	"host-pid":                         HostPID,
	"invalid-target-ports":             InvalidTargetPorta,
	"latest-tag":                       LatestTag,
	"mismatching-selector":             MismatchingSelector,
	"no-anti-affinity":                 NoAntiAffinity,
	"no-liveness-probe":                NoLivenessProbe,
	"no-read-only-root-fs":             NoReadOnlyRootFS,
	"no-readiness-probe":               NoReadinessProe,
	"no-rolling-update-strategy":       NoRollingUpdateStrategy,
	"privilege-escalation-container":   PrivilegeEsxalationContainer,
	"privileged-container":             PrivilegedContainer,
	"privileged-ports":                 PrivilegedProts,
	"run-as-non-root":                  RunAsNonRoot,
	"sensitive-host-mounts":            SensitiveHostMounts,
	"ssh-port":                         SSHPort,
	"unsafe-proc-mount":                UnsafeProcMount,
	"unsafe-sysctls":                   UnsafeSysctls,
	"unset-memory-requirements":        UnsetMempryRequirements,
	"use-namespace":                    UseNamespace,
	"writable-host-mount":              WritableHostMount,
	// CIS 4.1
	"cluster-admin-role-binding": ClusterAdminRoleBinding,
	"access-to-secrets":          AccessToSecrets,
	"wildcard-in-rules":          WildcardInRules,
	"access-to-create-pods":      AccessToCreatePods,
	"default-service-account":    DefaultServiceAccount,
	"sa-token-automount":         TokenAutomount,
}

type LinterCheck struct {
	ResourceID string         `json:"resourceID"`
	Passed     *LinterRuleSet `json:"passed"`
	Failed     *LinterRuleSet `json:"failed"`
}

func (s *LinterRuleSet) Add(i LinterRule) {
	v := LinterRule(*s)
	v |= i

	*s = LinterRuleSet(v)
}

func (s *LinterRuleSet) Has(i LinterRule) bool {
	return LinterRule(*s)&i != 0
}

func (s *LinterRuleSet) Rules() []string {
	result := make([]string, 0)
	for name, mask := range LinterRuleMap {
		if LinterRule(*s)&mask != 0 {
			result = append(result, name)
		}
	}

	return result
}

type Resource struct {
	ObjectMeta ObjectMeta
	ObjectType ObjectType
}

type ObjectMeta struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type ObjectType struct {
	APIVersion string `json:"APIVersion"`
	Kind       string `json:"kind"`
}

func (r Resource) ObjectKey() string {
	return fmt.Sprintf(
		"%s/%s/%s/%s",
		r.ObjectType.APIVersion,
		r.ObjectType.Kind,
		r.ObjectMeta.Namespace,
		r.ObjectMeta.Name,
	)
}
