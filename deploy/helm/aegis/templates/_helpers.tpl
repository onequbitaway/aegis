{{/* The name of the chart. */}}
{{- define "aegis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* The name of each object of the release. */}}
{{- define "aegis.fullname" -}}
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

{{/* The labels that select the pod. */}}
{{- define "aegis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aegis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* The labels of each object. */}}
{{- define "aegis.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "aegis.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aegis
{{- end }}

{{/* The name of the ServiceAccount of the pod. */}}
{{- define "aegis.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "aegis.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* The image reference. A digest has priority over the tag. */}}
{{- define "aegis.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/* The name of the claim for /var/lib/aegis. */}}
{{- define "aegis.claimName" -}}
{{- default (printf "%s-data" (include "aegis.fullname" .)) .Values.persistence.existingClaim }}
{{- end }}

{{/* The name of the Secret with the credentials. The chart stops if a credential needs it and it has no name. */}}
{{- define "aegis.secretName" -}}
{{- required "credentials.existingSecret is necessary: the configuration uses a credential. Make the Secret first and give its name." .Values.credentials.existingSecret }}
{{- end }}

{{/* The modules of the process. The operator API adds the module `api`. */}}
{{- define "aegis.modules" -}}
{{- $modules := without .Values.config.modules "api" }}
{{- if .Values.api.enabled }}
{{- $modules = append $modules "api" }}
{{- end }}
{{- toJson $modules }}
{{- end }}

{{/*
Stops the installation for a set of values that cannot work. Each message names the
value to change.
*/}}
{{- define "aegis.validate" -}}
{{- if gt (int .Values.replicaCount) 1 }}
{{- fail "replicaCount must be 0 or 1. The file audit log has one writer, and the state of the detection engine is in the memory of one process. AEGIS has no high-availability mode at this time." }}
{{- end }}
{{- if not (has .Values.bus.kind (list "memory" "nats")) }}
{{- fail "bus.kind must be `memory` or `nats`." }}
{{- end }}
{{- if not (has .Values.bus.nats.auth.method (list "none" "token" "user_password" "credentials_file")) }}
{{- fail "bus.nats.auth.method must be `none`, `token`, `user_password`, or `credentials_file`." }}
{{- end }}
{{- if and (eq .Values.bus.nats.auth.method "credentials_file") (not .Values.bus.nats.auth.credentialsFile) }}
{{- fail "bus.nats.auth.credentialsFile is necessary for the method `credentials_file`." }}
{{- end }}
{{- if not (has .Values.storage.kind (list "memory" "postgres")) }}
{{- fail "storage.kind must be `memory` or `postgres`." }}
{{- end }}
{{- if not (has .Values.audit.kind (list "file" "postgres")) }}
{{- fail "audit.kind must be `file` or `postgres`." }}
{{- end }}
{{- if and (eq .Values.audit.kind "postgres") (ne .Values.storage.kind "postgres") }}
{{- fail "audit.kind `postgres` needs storage.kind `postgres`." }}
{{- end }}
{{- if and .Values.ingress.enabled (not .Values.api.enabled) }}
{{- fail "ingress.enabled needs api.enabled: the Ingress sends requests to the operator API." }}
{{- end }}
{{- if and .Values.api.enabled (not .Values.api.principals) (not .Values.config.aegisToml) }}
{{- fail "api.principals must have one principal or more. The operator API has no open mode." }}
{{- end }}
{{- end }}
