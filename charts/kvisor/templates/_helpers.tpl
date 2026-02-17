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
{{- if and .Values.castai.clusterID (or .Values.castai.clusterIdConfigMapKeyRef.name .Values.castai.clusterIdSecretKeyRef.name) }}
  {{- fail "clusterID cannot be used together with clusterIdConfigMapKeyRef or clusterIdSecretKeyRef" }}
{{- else if .Values.castai.clusterID }}
- name: CLUSTER_ID
  value: {{ .Values.castai.clusterID | quote }}
{{- else if .Values.castai.clusterIdConfigMapKeyRef.name }}
- name: CLUSTER_ID
  valueFrom:
    configMapKeyRef:
      name: {{ .Values.castai.clusterIdConfigMapKeyRef.name }}
      key: {{ .Values.castai.clusterIdConfigMapKeyRef.key }}
{{- else if .Values.castai.clusterIdSecretKeyRef.name }}
- name: CLUSTER_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.castai.clusterIdSecretKeyRef.name }}
      key: {{ .Values.castai.clusterIdSecretKeyRef.key }}
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
Common helpers for clickhouse.
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
