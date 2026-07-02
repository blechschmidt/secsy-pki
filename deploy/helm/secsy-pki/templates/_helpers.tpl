{{/* Expand the name of the chart. */}}
{{- define "secsy-pki.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name. */}}
{{- define "secsy-pki.fullname" -}}
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

{{- define "secsy-pki.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "secsy-pki.labels" -}}
helm.sh/chart: {{ include "secsy-pki.chart" . }}
{{ include "secsy-pki.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "secsy-pki.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secsy-pki.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "secsy-pki.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "secsy-pki.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Image reference, defaulting the tag to the chart appVersion. */}}
{{- define "secsy-pki.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/* Name of the Secret holding the HSM PIN and root password. */}}
{{- define "secsy-pki.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "secsy-pki.fullname" . }}
{{- end }}
{{- end }}

{{/* URL scheme for probes/ServiceMonitor: HTTP only when running cleartext. */}}
{{- define "secsy-pki.scheme" -}}
{{- if .Values.tls.allowInsecureHTTP }}HTTP{{- else }}HTTPS{{- end }}
{{- end }}

{{/* Whether server TLS is served directly by the pod (vs. terminated upstream). */}}
{{- define "secsy-pki.podTLSEnabled" -}}
{{- if or .Values.tls.existingSecret .Values.tls.certManager.enabled }}true{{- end }}
{{- end }}

{{/* Name of the Secret holding the server's TLS cert/key, if any. */}}
{{- define "secsy-pki.tlsSecretName" -}}
{{- if .Values.tls.existingSecret }}
{{- .Values.tls.existingSecret }}
{{- else if .Values.tls.certManager.enabled }}
{{- printf "%s-tls" (include "secsy-pki.fullname" .) }}
{{- end }}
{{- end }}

{{/* In-cluster ACME directory URL used by the rendered cert-manager issuer. */}}
{{- define "secsy-pki.acmeDirectoryURL" -}}
{{- if .Values.certManager.clusterIssuer.server }}
{{- .Values.certManager.clusterIssuer.server }}
{{- else }}
{{- $scheme := "https" }}
{{- if .Values.tls.allowInsecureHTTP }}{{ $scheme = "http" }}{{- end }}
{{- printf "%s://%s.%s.svc:%d/acme/directory" $scheme (include "secsy-pki.fullname" .) .Release.Namespace (int .Values.service.port) }}
{{- end }}
{{- end }}
