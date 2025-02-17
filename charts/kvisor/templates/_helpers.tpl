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
