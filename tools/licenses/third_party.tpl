{{- /*
Template used by `go-licenses report` to generate THIRD_PARTY_NOTICES files.
Output: one row per module, with the SPDX license identifier and the upstream URL.
*/ -}}
| Module | License | Source |
| --- | --- | --- |
{{- range . }}
| {{.Name}} | {{.LicenseName}} | {{.LicenseURL}} |
{{- end }}
