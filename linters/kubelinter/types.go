package kubelinter

import "github.com/castai/sec-agent/types"

var Rules = map[string]types.CheckMeta{
	"dangling-service": {
		DisplayName: "Dangling service",
		Description: "Checks if services do not have any associated deployments.",
		Category:    "best-practice",
		CVSS3Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
	},
	"deprecated-service-account-field": {
		DisplayName: "Deprecated service account",
		Description: "Checks if deployments use the deprecated serviceAccount field.",
		Category:    "best-practice",
	},
	"docker-sock": {
		DisplayName: "Docker sock mount",
		Description: "Checks if deployments have docker.sock mounted in containers.",
		Severity:    8.7,
		Category:    "best-practice",
	},
	"drop-net-raw-capability": {
		DisplayName: "Drop NET_RAW capability",
		Description: "Checks if containers do not drop NET_RAW capability",
		Severity:    3.8,
		Category:    "best-practice",
	},
	"env-var-secret": {
		DisplayName: "Secrets in environment variable",
		Description: "Checks if objects use a secret in an environment variable.",
		Severity:    6.2,
		Category:    "best-practice",
	},
	"exposed-services": {
		DisplayName: "Exposed services",
		Description: "Checks services for forbidden types.",
		Severity:    5.3,
		Category:    "best-practice",
	},
	"host-ipc": {
		DisplayName: "Host IPC",
		Description: "Checks if pods/deployment-likes are sharing host's IPC namespace.",
		Severity:    8.1,
		Category:    "best-practice",
	},
	"host-network": {
		DisplayName: "Host network",
		Description: "Checks if pods/deployment-likes are sharing host's network namespace.",
		Severity:    6.3,
		Category:    "best-practice",
	},
	"host-pid": {
		DisplayName: "Host PID",
		Description: "Checks if pods/deployment-likes are sharing host's process namespace.",
		Severity:    5.1,
		Category:    "best-practice",
	},
	"invalid-target-ports": {
		DisplayName: "Invalid target ports",
		Description: "Checks if deployments or services are using port names that are violating specifications.",
		Category:    "best-practice",
	},
	"latest-tag": {
		DisplayName: "Latest tag",
		Description: "Checks if a deployment-like object is running a container with an invalid container image",
		Severity:    4.5,
		Category:    "best-practice",
	},
	"mismatching-selector": {
		DisplayName: "Mismatching selector",
		Description: "Checks if deployment selectors fail to match the pod template labels.",
		Category:    "best-practice",
	},
	"no-anti-affinity": {
		DisplayName: "No anti-affinity",
		Description: "Checks if deployments with multiple replicas does not specify inter-pod anti-affinity," +
			" to ensure that the orchestrator attempts to schedule replicas on different nodes.",
		Category: "best-practice",
	},
	"no-liveness-probe": {
		DisplayName: "No liveness probe",
		Description: "Checks if containers fail to specify a liveness probe.",
		Category:    "best-practice",
	},
	"no-read-only-root-fs": {
		DisplayName: "No read-only root FS",
		Description: "Checks if containers are running without a read-only root filesystem.",
		Severity:    4.5,
		Category:    "best-practice",
	},
	"no-readiness-probe": {
		DisplayName: "No readiness probe",
		Description: "Checks if containers fail to specify a readiness probe.",
		Category:    "best-practice",
	},
	"no-rolling-update-strategy": {
		DisplayName: "No rolling update strategy",
		Description: "Checks if a deployment doesn't use a rolling update strategy.",
		Category:    "best-practice",
	},
	"privilege-escalation-container": {
		DisplayName: "Privilege escalation",
		Description: "Checks if containers of allowing privilege escalation that could gain more privileges" +
			" than its parent process.",
		Severity: 7.1,
		Category: "best-practice",
	},
	"privileged-container": {
		DisplayName: "Privileged container",
		Description: "Checks if deployments have containers running in privileged mode.",
		Severity:    5.9,
		Category:    "best-practice",
	},
	"privileged-ports": {
		DisplayName: "Privileged ports",
		Description: "Checks if deployments with privileged ports mapped in containers.",
		Severity:    4.5,
		Category:    "best-practice",
	},
	"run-as-non-root": {
		DisplayName: "Run as non-root",
		Description: "Checks if containers are not set to runAsNonRoot.",
		Severity:    5.9,
		Category:    "best-practice",
	},
	"sensitive-host-mounts": {
		DisplayName: "Sensitive host mounts",
		Description: "Checks if deployments with sensitive host system directories mounted in containers.",
		Severity:    6.7,
		Category:    "best-practice",
	},
	"ssh-port": {
		DisplayName: "Exposed SSH port",
		Description: "Checks if deployments expose port 22, which is commonly reserved for SSH access.",
		Severity:    6.6,
		Category:    "best-practice",
	},
	"unsafe-proc-mount": {
		DisplayName: "Unsafe /proc mount",
		Description: "Checks if deployments with unsafe /proc mount (procMount=Unmasked) that will bypass" +
			" the default masking behavior of the container runtime.",
		Severity: 5.0,
		Category: "best-practice",
	},
	"unsafe-sysctls": {
		DisplayName: "Unsafe sysctls",
		Description: "Checks if deployments specifying unsafe sysctls that may lead to severe problems" +
			" like wrong behavior of containers.",
		Severity: 3.9,
		Category: "best-practice",
	},
	"unset-memory-requirements": {
		DisplayName: "Unset memory requirements",
		Description: "Checks if containers do not have memory requests and limits set.",
		Severity:    2.3,
		Category:    "best-practice",
	},
	"use-namespace": {
		DisplayName: "Use namespace",
		Description: "Checks if a resource is deployed to the default namespace.",
		Category:    "best-practice",
	},
	"writable-host-mount": {
		DisplayName: "Writeable host mount",
		Description: "Checks for containers that have mounted a directory on the host as writable.",
		Severity:    7.8,
		Category:    "best-practice",
	},
}
