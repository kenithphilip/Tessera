{{/*
Expand the name of the chart.
*/}}
{{- define "tessera-mesh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully-qualified app name.
Truncated at 63 characters because Kubernetes name fields are limited.
If release name already contains the chart name, the chart name is not appended.
*/}}
{{- define "tessera-mesh.fullname" -}}
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
Create chart label value: chart name + version with dots replaced so it is a
valid label value.
*/}}
{{- define "tessera-mesh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "tessera-mesh.labels" -}}
helm.sh/chart: {{ include "tessera-mesh.chart" . }}
{{ include "tessera-mesh.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
tessera.dev/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/*
Selector labels used by the Deployment and Service.
*/}}
{{- define "tessera-mesh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tessera-mesh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name to use.
*/}}
{{- define "tessera-mesh.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "tessera-mesh.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret that holds signing keys.
Returns the existingSecret name when set, otherwise the chart-managed stub.
*/}}
{{- define "tessera-mesh.signingSecretName" -}}
{{- if .Values.signing.existingSecret }}
{{- .Values.signing.existingSecret }}
{{- else }}
{{- include "tessera-mesh.fullname" . }}-signing
{{- end }}
{{- end }}
