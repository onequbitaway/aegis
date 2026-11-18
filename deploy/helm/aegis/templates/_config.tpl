{{/*
The text of `aegis.toml`. The file has no secret: the Deployment gives each credential
as an environment variable from the Secret `credentials.existingSecret`.
*/}}
{{- define "aegis.config" -}}
# The chart made this file from its values. A relative path starts at /etc/aegis.

[modules]
enabled = {{ include "aegis.modules" . }}

[telemetry]
service_name = {{ .Values.config.telemetry.serviceName | quote }}
log_format = {{ .Values.config.telemetry.logFormat | quote }}
log_level = {{ .Values.config.telemetry.logLevel | quote }}
{{- with .Values.config.telemetry.otlpEndpoint }}
otlp_endpoint = {{ . | quote }}
{{- end }}

[bus]
kind = {{ .Values.bus.kind | quote }}
{{- if eq .Values.bus.kind "nats" }}

[bus.nats]
urls = {{ toJson .Values.bus.nats.urls }}

[bus.nats.auth]
# The environment gives the token or the password.
method = {{ .Values.bus.nats.auth.method | quote }}
{{- if eq .Values.bus.nats.auth.method "user_password" }}
user = {{ .Values.bus.nats.auth.user | quote }}
{{- else if eq .Values.bus.nats.auth.method "credentials_file" }}
path = {{ .Values.bus.nats.auth.credentialsFile | quote }}
{{- end }}
{{- if or .Values.bus.nats.tls.required .Values.bus.nats.tls.caFile }}

[bus.nats.tls]
required = true
{{- with .Values.bus.nats.tls.caFile }}
ca_file = {{ . | quote }}
{{- end }}
{{- end }}

[bus.stream]
name = {{ .Values.bus.nats.stream.name | quote }}
replicas = {{ int .Values.bus.nats.stream.replicas }}
manage = {{ .Values.bus.nats.stream.manage }}
{{- end }}

[storage]
kind = {{ .Values.storage.kind | quote }}
{{- if eq .Values.storage.kind "postgres" }}
# The environment variable AEGIS__STORAGE__URL gives the database URL.
max_connections = {{ int .Values.storage.postgres.maxConnections }}
{{- end }}

[audit]
kind = {{ .Values.audit.kind | quote }}
{{- if eq .Values.audit.kind "file" }}
path = "/var/lib/aegis/audit.jsonl"
{{- end }}

[policy]
paths = {{ toJson .Values.config.policy.paths }}

[rbac.roles]
{{- range $role, $permissions := .Values.config.rbacRoles }}
{{ $role | quote }} = {{ toJson $permissions }}
{{- end }}

[approval]
four_eyes = {{ .Values.config.approval.fourEyes }}
humans_only = {{ .Values.config.approval.humansOnly }}

[detection]
pack = {{ .Values.config.detection.pack | quote }}

[agents]
goal = {{ .Values.config.agents.goal | quote }}
dry_run = {{ .Values.config.agents.dryRun }}

[response]
dry_run = {{ .Values.config.response.dryRun }}
playbooks = {{ .Values.config.response.playbooks | quote }}
{{- with .Values.config.response.playbookDir }}
playbook_dir = {{ . | quote }}
{{- end }}

[ingest]
checkpoint_dir = "/var/lib/aegis/checkpoints"
{{- if .Values.plugins.enabled }}

[plugins]
dir = "/plugins"
{{- end }}
{{- if .Values.api.enabled }}

# The server has no TLS. It listens on the pod address for the Service and the probes.
[api]
bind = "0.0.0.0:{{ int .Values.api.port }}"
allow_non_loopback = true
console = {{ .Values.api.console }}
{{- range .Values.api.principals }}

[[api.principals]]
id = {{ .id | quote }}
kind = {{ .kind | default "human" | quote }}
roles = {{ toJson .roles }}
{{- with .tokenEnv }}
token_env = {{ . | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- with .Values.config.extraToml }}

{{ . }}
{{- end }}
{{- end }}
