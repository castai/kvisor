{{/*
Expand the name of the chart.
*/}}
{{- define "kvisor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kvisor.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kvisor.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}


{{- define "kvisor.castaiSecretName" -}}
{{- if .Values.castai.apiKeySecretRef }}
{{- .Values.castai.apiKeySecretRef }}
{{- else }}
{{- .Release.Name }}
{{- end }}
{{- end }}

{{- define "kvisor.apiKeyEnvFrom" -}}
{{- $envFrom := .envFrom -}}
{{- if and .Values.castai.apiKey .Values.castai.apiKeySecretRef }}
  {{- fail "apiKey and apiKeySecretRef are mutually exclusive" }}
{{- else if .Values.castai.apiKey }}
- secretRef:
    name: {{ .Release.Name }}
{{- else if .Values.castai.apiKeySecretRef }}
- secretRef:
    name: {{ .Values.castai.apiKeySecretRef }}
{{- else if not $envFrom }}
  {{- fail "castai.apiKey or castai.apiKeySecretRef must be provided" }}
{{- end }}
{{- end }}

{{- define "kvisor.clusterIDEnv" -}}
{{- $envFrom := .envFrom -}}
{{- $clusterID := coalesce (dig "castai" "clusterID" "" (.Values.global | default dict)) .Values.castai.clusterID -}}
{{- if and $clusterID (or .Values.castai.clusterIdConfigMapKeyRef.name .Values.castai.clusterIdSecretKeyRef.name) }}
  {{- fail "clusterID cannot be used together with clusterIdConfigMapKeyRef or clusterIdSecretKeyRef" }}
{{- else if $clusterID }}
- name: CLUSTER_ID
  value: {{ $clusterID | quote }}
  valueFrom: null # workaround for https://github.com/helm/helm/issues/8994
{{- else if .Values.castai.clusterIdConfigMapKeyRef.name }}
- name: CLUSTER_ID
  valueFrom:
    configMapKeyRef:
      name: {{ .Values.castai.clusterIdConfigMapKeyRef.name }}
      key: {{ .Values.castai.clusterIdConfigMapKeyRef.key }}
  value: null # workaround for https://github.com/helm/helm/issues/8994
{{- else if .Values.castai.clusterIdSecretKeyRef.name }}
- name: CLUSTER_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.castai.clusterIdSecretKeyRef.name }}
      key: {{ .Values.castai.clusterIdSecretKeyRef.key }}
  value: null # workaround for https://github.com/helm/helm/issues/8994
{{- else if not $envFrom }}
  {{- fail "castai.clusterID, castai.clusterIdConfigMapKeyRef or castai.clusterIdSecretKeyRef must be provided" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}

{{- define "kvisor.commonLabels" -}}
{{- range $key, $value := .Values.commonLabels }}
{{$key}}: {{$value}}
{{- end }}
{{- end }}

{{- define "kvisor.labels" -}}
helm.sh/chart: {{ include "kvisor.chart" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{ include "kvisor.commonLabels" . }}
{{- end }}

{{/*
Common helpers for runtime agent.
*/}}
{{- define "kvisor.agent.serviceAccountName" -}}
{{- if .Values.agent.serviceAccount.create }}
{{- default (include "kvisor.fullname" .) .Values.agent.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.agent.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "kvisor.agent.fullname" -}}
{{ include "kvisor.fullname" . }}-agent
{{- end }}

{{- define "kvisor.agent.labels" -}}
{{ include "kvisor.labels" . }}
{{ include "kvisor.agent.selectorLabels" . }}
{{- end }}

{{- define "kvisor.agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kvisor.agent.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end }}

{{/*
Common helpers for controller.
*/}}
{{- define "kvisor.controller.serviceAccountName" -}}
{{- if .Values.controller.serviceAccount.create }}
{{- default (include "kvisor.controller.fullname" .) .Values.controller.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.controller.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "kvisor.controller.fullname" -}}
{{ include "kvisor.fullname" . }}-controller
{{- end }}

{{- define "kvisor.controller.labels" -}}
{{ include "kvisor.labels" . }}
{{ include "kvisor.controller.selectorLabels" . }}
{{- end }}

{{- define "kvisor.controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kvisor.controller.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: controller
{{- end }}


{{/*
Common helpers for cluster proxy.
*/}}
{{- define "kvisor.clusterproxy.fullname" -}}
{{ include "kvisor.fullname" . }}-cluster-proxy
{{- end }}

{{- define "kvisor.clusterproxy.serviceAccountName" -}}
{{ include "kvisor.clusterproxy.fullname" . }}
{{- end }}


{{/*
Common helpers for event generator.
*/}}
{{- define "kvisor.eventGenerator.fullname" -}}
{{ include "kvisor.fullname" . }}-event-generator
{{- end }}

{{- define "kvisor.eventGenerator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kvisor.name" . }}-event-generator
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kvisor.eventGenerator.labels" -}}
{{ include "kvisor.labels" . }}
{{ include "kvisor.eventGenerator.selectorLabels" . }}
{{- end }}

{{- define "kvisor.eventGenerator.serviceAccountName" -}}
{{ include "kvisor.eventGenerator.fullname" . }}
{{- end }}


{{/*
Common helpers for castai-mock-server.
*/}}
{{- define "kvisor.castaiMockServer.fullname" -}}
{{ include "kvisor.fullname" . }}-castai-mock-server
{{- end }}

{{- define "kvisor.castaiMockServer.service" -}}
{{ include "kvisor.fullname" . }}-castai-mock-server
{{- end }}

{{- define "kvisor.castaiMockServer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kvisor.name" . }}-mock-castai-server
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kvisor.castaiMockServer.labels" -}}
{{ include "kvisor.labels" . }}
{{- end }}


{{/*
ClickHouse helpers for legacy netflow deployment.
*/}}
{{- define "kvisor.clickhouse.fullname" -}}
{{ include "kvisor.fullname" . }}-clickhouse
{{- end }}

{{- define "kvisor.clickhouse.service" -}}
{{ include "kvisor.fullname" . }}-clickhouse
{{- end }}

{{- define "kvisor.clickhouse.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kvisor.name" . }}-clickhouse
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kvisor.clickhouse.labels" -}}
{{ include "kvisor.labels" . }}
{{- end }}

{{/*
Reliability metrics ClickHouse helpers (for subchart).
*/}}
{{- define "kvisor.reliabilityMetrics.clickhouse.fullname" -}}
{{- printf "%s-clickhouse" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "kvisor.reliabilityMetrics.clickhouse.credentialsSecretName" -}}
{{ include "kvisor.reliabilityMetrics.clickhouse.fullname" . }}-credentials
{{- end -}}

{{- define "kvisor.reliabilityMetrics.clickhouse.address" -}}
{{- if (dig "external" "enabled" false .Values.reliabilityMetrics) -}}
{{ .Values.reliabilityMetrics.external.address }}
{{- else if (dig "install" "enabled" false .Values.reliabilityMetrics) -}}
{{ include "kvisor.reliabilityMetrics.clickhouse.fullname" . }}.{{ .Release.Namespace }}.svc.cluster.local:9000
{{- end -}}
{{- end -}}

{{- define "kvisor.reliabilityMetrics.clickhouse.database" -}}
{{- if and .Values.reliabilityMetrics.external .Values.reliabilityMetrics.external.enabled .Values.reliabilityMetrics.external.database -}}
{{- .Values.reliabilityMetrics.external.database -}}
{{- else if .Values.reliabilityMetrics.auth -}}
{{- .Values.reliabilityMetrics.auth.database -}}
{{- else -}}
metrics
{{- end -}}
{{- end -}}

{{/*
Reliability metrics ClickHouse username - returns either direct value or valueFrom configMapKeyRef
Supports both plain string and valueFrom object in auth.username
*/}}
{{- define "kvisor.reliabilityMetrics.clickhouse.username" -}}
{{- $username := dig "auth" "username" "kvisor" .Values.reliabilityMetrics -}}
{{- if kindIs "string" $username -}}
value: {{ $username | quote }}
{{- else if and (kindIs "map" $username) $username.valueFrom -}}
{{- toYaml $username | nindent 0 }}
{{- else -}}
value: "kvisor"
{{- end -}}
{{- end -}}

{{/*
Reliability metrics ClickHouse password - returns either direct value or valueFrom secretKeyRef
Supports both plain string and valueFrom object in auth.password
*/}}
{{- define "kvisor.reliabilityMetrics.clickhouse.password" -}}
{{- $password := dig "auth" "password" "kvisor" .Values.reliabilityMetrics -}}
{{- if kindIs "string" $password -}}
value: {{ $password | quote }}
{{- else if and (kindIs "map" $password) $password.valueFrom -}}
{{- toYaml $password | nindent 0 }}
{{- else -}}
value: "kvisor"
{{- end -}}
{{- end -}}


{{/*
Agent container security context with conditional capabilities.
If capabilities.add is already defined in values.yaml, those are used as-is.
Otherwise, capabilities are added dynamically based on enabled features in extraArgs:

When ebpf-events-enabled or netflow-enabled:
  - BPF: Required for loading eBPF programs and the creation of eBPF maps
  - SYS_ADMIN: Required for eBPF operations on older kernels
  - SYS_PTRACE: Required for reading /proc/[pid]/ns and /proc/1/root paths
  - SYS_RESOURCE: Required for rlimit adjustments
  - NET_ADMIN: Required for loading network programs
  - PERFMON: Required for loading tracing programs
  - IPC_LOCK: Required for mmap
  - SYSLOG: Required for resolving /proc/kallsyms

When storage-stats-enabled (without eBPF):
  - SYS_PTRACE: Required for accessing /proc/1/root paths for storage metrics
*/}}
{{- define "kvisor.agent.containerSecurityContext" -}}
{{- $secCtx := deepCopy .Values.agent.containerSecurityContext -}}
{{- /* Only add capabilities dynamically if not already defined in values */ -}}
{{- if not $secCtx.capabilities.add -}}
  {{- $needsEbpfCaps := or
    (eq (index .Values.agent.extraArgs "ebpf-events-enabled") true)
    (eq (index .Values.agent.extraArgs "netflow-enabled") true)
  -}}
  {{- $needsStorageCaps := eq (index .Values.agent.extraArgs "storage-stats-enabled") true -}}
  {{- if $needsEbpfCaps -}}
    {{- $ebpfCaps := list
      "BPF"
      "SYS_ADMIN"
      "SYS_PTRACE"
      "SYS_RESOURCE"
      "NET_ADMIN"
      "PERFMON"
      "IPC_LOCK"
      "SYSLOG"
    -}}
    {{- $_ := set $secCtx.capabilities "add" $ebpfCaps -}}
  {{- else if $needsStorageCaps -}}
    {{- /* Storage stats only needs SYS_PTRACE to access /proc/1/root paths */ -}}
    {{- $storageCaps := list "SYS_PTRACE" -}}
    {{- $_ := set $secCtx.capabilities "add" $storageCaps -}}
  {{- end -}}
{{- end -}}
{{- toYaml $secCtx -}}
{{- end -}}

{{/*
Resolve cloud provider for --cloud-provider arg.
Only used as a fallback when controller.extraArgs.cloud-provider is not set.
*/}}
{{- define "kvisor.cloudProvider" -}}
{{- dig "castai" "provider" "" (.Values.global | default dict) -}}
{{- end }}

{{/*
Returns true if GPU metrics collection is enabled.
*/}}
{{- define "kvisor.gpuEnabled" -}}
{{- if dig "gpu" "enabled" false .Values.agent }}true{{- end -}}
{{- end }}

{{/*
Resolve CASTAI_API_URL: global.castai.apiURL > .Values.castai.apiURL
*/}}
{{- define "kvisor.apiURL" -}}
{{- coalesce (dig "castai" "apiURL" "" (.Values.global | default dict)) .Values.castai.apiURL -}}
{{- end }}

{{/*
OBI (OpenTelemetry eBPF Instrumentation) sidecar container security context.
Uses fine-grained capabilities instead of privileged: true.
Capabilities: BPF, SYS_PTRACE, NET_RAW, CHECKPOINT_RESTORE, DAC_READ_SEARCH, PERFMON.
Can be overridden via .Values.agent.reliabilityMetrics.obi.containerSecurityContext.
*/}}
{{- define "kvisor.obi.containerSecurityContext" -}}
    {{- $override := .Values.agent.reliabilityMetrics.obi.containerSecurityContext -}}
{{- if $override }}
{{- toYaml $override }}
{{- else }}
runAsUser: 0
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
  add:
    - BPF
    - SYS_ADMIN
    - SYS_PTRACE
    - NET_RAW
    - CHECKPOINT_RESTORE
    - DAC_READ_SEARCH
    - PERFMON
{{- end }}
{{- end }}

{{/*https://github.com/kubernetes/kubernetes/issues/91514#issuecomment-2209311103*/}}
{{- define "GOMEMLIMITEnv" -}}
{{- $memory := . -}}
{{- if $memory -}}
- name: GOMEMLIMIT
  {{- $value := regexFind "^\\d*\\.?\\d+" $memory | float64 -}}
  {{- $unit := regexFind "[A-Za-z]+" $memory -}}
  {{- $valueMi := 0.0 -}}
  {{- if eq $unit "Gi" -}}
    {{- $valueMi = mulf $value 1024 -}}
  {{- else if eq $unit "Mi" -}}
    {{- $valueMi = $value -}}
  {{- end -}}
  {{- $percentageValue := int (mulf $valueMi 0.9) }}
  value: {{ printf "%dMiB" $percentageValue -}}
{{- end -}}
{{- end -}}

{{/*
MemoryLimiterEnv derives the OTel memory_limiter processor limits from the
container memory limit. limit_mib = 80% of container limit, spike_limit_mib =
25% of limit_mib. The resulting soft limit (limit - spike) is ~60% of the
container limit, leaving headroom for Go GC (GOMEMLIMIT at 90%).
*/}}
{{- define "MemoryLimiterEnv" -}}
{{- $memory := . -}}
{{- if $memory -}}
{{- $value := regexFind "^\\d*\\.?\\d+" $memory | float64 -}}
{{- $unit := regexFind "[A-Za-z]+" $memory -}}
{{- $valueMi := 0.0 -}}
{{- if eq $unit "Gi" -}}
  {{- $valueMi = mulf $value 1024 -}}
{{- else if eq $unit "Mi" -}}
  {{- $valueMi = $value -}}
{{- end -}}
{{- $limitMib := int (mulf $valueMi 0.8) -}}
{{- $spikeMib := int (mulf (float64 $limitMib) 0.25) }}
- name: MEMORY_LIMITER_LIMIT_MIB
  value: {{ printf "%d" $limitMib | quote }}
- name: MEMORY_LIMITER_SPIKE_LIMIT_MIB
  value: {{ printf "%d" $spikeMib | quote }}
{{- end -}}
{{- end -}}

{{/*
Map OBI sizing profile name to resource requests and limits.
Accepts the full .Values.agent.reliabilityMetrics.obi context.
Usage: {{ include "kvisor.obi.profileResources" .Values.agent.reliabilityMetrics.obi }}

Profiles:
  small  — up to 5 services/node   (requests: 96Mi,  limits: 256Mi)
  medium — 5–15 services/node      (requests: 192Mi, limits: 512Mi)
  large  — 15–30 services/node     (requests: 384Mi, limits: 768Mi)
  xlarge — 30+ services/node       (requests: 512Mi, limits: 1Gi)
  custom — uses the explicit .resources block
*/}}
{{- define "kvisor.obi.profileResources" -}}
{{- $profile := .sizingProfile | default "medium" -}}
{{- if eq $profile "small" }}
requests:
  memory: 96Mi
limits:
  memory: 256Mi
{{- else if eq $profile "medium" }}
requests:
  memory: 192Mi
limits:
  memory: 512Mi
{{- else if eq $profile "large" }}
requests:
  memory: 384Mi
limits:
  memory: 768Mi
{{- else if eq $profile "xlarge" }}
requests:
  memory: 512Mi
limits:
  memory: 1Gi
{{- else }}
{{- /* "custom" or any unknown value → use explicit resources block */ -}}
{{ .resources | toYaml }}
{{- end }}
{{- end -}}

{{/*
OBI init container. Always included when reliability metrics are enabled.
Sets up an entrypoint that derives GOMEMLIMIT from OBI_MEMORY_LIMIT_BYTES (injected
via Kubernetes Downward API resourceFieldRef). This ensures GOMEMLIMIT tracks VPA
adjustments, LimitRange mutations, or any other post-render changes.

When dynamicSizing is enabled, also scans all network namespaces on the node to
count listening sockets on configured openPorts, and writes a recommendation to
/shared/obi-recommended-mem for the entrypoint to log.

Formula (dynamicSizing): memory = 40 + (N × 27) + 30 MiB, clamped to [120, 1024] MiB
*/}}
{{- define "kvisor.obi.initContainer" -}}
- name: obi-init
  image: "busybox:1.37.0-musl"
  securityContext:
    runAsUser: 0
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false
    capabilities:
    {{- if (dig "reliabilityMetrics" "obi" "dynamicSizing" false .Values.agent) }}
      add: ["SYS_PTRACE"]
    {{- end }}
      drop: ["ALL"]
  command: ["sh", "-c"]
  args:
    - |
      {{- if (dig "reliabilityMetrics" "obi" "dynamicSizing" false .Values.agent) }}
      # ── Dynamic sizing: count processes across all network namespaces ──
      PORTS="{{ .Values.agent.reliabilityMetrics.obi.openPorts }}"

      HEX_PATTERN=$(echo "$PORTS" | tr ',' '\n' | while read p; do
        printf '%04X\n' "$p"
      done | paste -sd'|' -)

      # Discover unique network namespaces and pick one representative PID per netns.
      # Each pod has its own netns; hostPID=true lets us see all PIDs on the node.
      : > /shared/obi_seen_ns
      : > /shared/obi_sockets
      for pid_dir in /proc/[0-9]*; do
        pid="${pid_dir##*/}"
        ns=$(readlink "${pid_dir}/ns/net" 2>/dev/null) || continue
        grep -qxF "$ns" /shared/obi_seen_ns 2>/dev/null && continue
        echo "$ns" >> /shared/obi_seen_ns
        cat "/proc/${pid}/net/tcp" "/proc/${pid}/net/tcp6" 2>/dev/null \
          | awk -v ns="$ns" '$4 == "0A" {print ns ":" $2}' >> /shared/obi_sockets
      done

      NS_COUNT=$(wc -l < /shared/obi_seen_ns | tr -d ' ')
      COUNT=$(sort -u /shared/obi_sockets \
        | awk -F: '{print $NF}' \
        | grep -cE "$HEX_PATTERN" \
      ) || COUNT=0
      rm -f /shared/obi_seen_ns /shared/obi_sockets

      [ "$COUNT" -eq 0 ] && COUNT=5

      MEM=$((40 + COUNT * 27 + 30))
      [ "$MEM" -lt 120 ] && MEM=120
      [ "$MEM" -gt 1024 ] && MEM=1024

      echo "obi-init: scanned $NS_COUNT network namespaces, found $COUNT listening processes on ports [$PORTS]"
      echo "obi-init: recommended memory = ${MEM} MiB (formula: 40 + $COUNT x 27 + 30)"
      echo "${COUNT} ${MEM}" > /shared/obi-recommended-mem
      {{- end }}

      # ── Copy busybox and create cgroup-aware entrypoint ──
      cp /bin/busybox /shared/busybox
      chmod +x /shared/busybox

      # Build entrypoint script line-by-line (heredocs break Helm YAML indentation).
      # The entrypoint reads the container's actual cgroup memory limit at runtime,
      # so GOMEMLIMIT always matches what the kubelet enforces — even after VPA changes.
      {
        echo '#!/shared/busybox sh'
        echo 'E=/shared/busybox'
        echo ''
        echo '# ── Read container memory limit ──'
        echo '# OBI_MEMORY_LIMIT_BYTES is injected via Kubernetes Downward API (resourceFieldRef).'
        echo '# This works in all privilege modes and tracks VPA mutations automatically.'
        echo 'LIMIT_BYTES="$OBI_MEMORY_LIMIT_BYTES"'
        echo ''
        echo '# ── Derive GOMEMLIMIT as 90% of container limit ──'
        echo 'if [ -n "$LIMIT_BYTES" ] && [ "$LIMIT_BYTES" -gt 0 ] 2>/dev/null; then'
        echo '  LIMIT_MIB=$((LIMIT_BYTES / 1048576))'
        echo '  GOMEMLIMIT_VAL=$((LIMIT_MIB * 9 / 10))'
        echo '  export GOMEMLIMIT="${GOMEMLIMIT_VAL}MiB"'
        echo '  $E echo "obi: GOMEMLIMIT=${GOMEMLIMIT} (90% of ${LIMIT_MIB}MiB cgroup limit)"'
        echo 'else'
        echo '  $E echo "obi: WARNING: OBI_MEMORY_LIMIT_BYTES not set, using default GOMEMLIMIT"'
        echo 'fi'
        echo ''
        echo '# ── Compare with dynamic sizer recommendation if available ──'
        echo 'if [ -f /shared/obi-recommended-mem ]; then'
        echo '  read PROC_COUNT RECOMMENDED < /shared/obi-recommended-mem'
        echo '  $E echo "obi: dynamic sizer found $PROC_COUNT processes, recommended ${RECOMMENDED}MiB"'
        echo '  if [ -n "$LIMIT_MIB" ] && [ "$RECOMMENDED" -gt "$LIMIT_MIB" ]; then'
        echo '    $E echo "obi: WARNING: recommended ${RECOMMENDED}MiB exceeds container limit ${LIMIT_MIB}MiB — risk of OOMKill"'
        echo '    $E echo "obi: WARNING: increase sizingProfile or set custom memory limit >= ${RECOMMENDED}Mi"'
        echo '  fi'
        echo 'fi'
        echo ''
        echo 'exec /obi'
      } > /shared/entrypoint.sh
      chmod +x /shared/entrypoint.sh
      echo "obi-init: entrypoint ready"
  volumeMounts:
    - name: obi-shared
      mountPath: /shared
{{- end -}}
