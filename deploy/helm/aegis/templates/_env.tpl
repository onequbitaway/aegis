{{/*
The environment of the AEGIS container. Each credential comes from the Secret
`credentials.existingSecret`. The chart never puts a credential in a manifest.

A variable with the prefix `AEGIS__` sets one key of the configuration. AEGIS reads its
text as a TOML value, so a token of only digits would become a number. The quotation
marks around `$(...)` make the value a TOML string.
*/}}
{{- define "aegis.env" -}}
{{- if eq .Values.storage.kind "postgres" }}
- name: AEGIS__STORAGE__URL
  valueFrom:
    secretKeyRef:
      name: {{ include "aegis.secretName" . }}
      key: {{ .Values.storage.postgres.secretKey }}
{{- end }}
{{- if and (eq .Values.bus.kind "nats") (has .Values.bus.nats.auth.method (list "token" "user_password")) }}
- name: AEGIS_NATS_CREDENTIAL
  valueFrom:
    secretKeyRef:
      name: {{ include "aegis.secretName" . }}
      key: {{ .Values.bus.nats.auth.secretKey }}
{{- if eq .Values.bus.nats.auth.method "token" }}
- name: AEGIS__BUS__NATS__AUTH__TOKEN
  value: '"$(AEGIS_NATS_CREDENTIAL)"'
{{- else }}
- name: AEGIS__BUS__NATS__AUTH__PASSWORD
  value: '"$(AEGIS_NATS_CREDENTIAL)"'
{{- end }}
{{- end }}
{{- if .Values.api.enabled }}
{{- range .Values.api.principals }}
{{- if .tokenEnv }}
- name: {{ .tokenEnv }}
  valueFrom:
    secretKeyRef:
      name: {{ include "aegis.secretName" $ }}
      key: {{ required (printf "api.principals: the principal %s has tokenEnv and needs secretKey." .id) .secretKey }}
{{- end }}
{{- end }}
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}
