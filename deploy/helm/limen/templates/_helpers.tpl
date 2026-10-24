{{- define "limen.image" -}}
{{- $reg := .root.Values.image.registry -}}
{{- $tag := required "image.tag is required" .root.Values.image.tag -}}
{{- if $reg }}{{ $reg }}/{{ end }}limen-{{ .component }}:{{ $tag }}
{{- end -}}

{{/* limen.selector: dict "component" "control-plane" "key" "core" */}}
{{- define "limen.selector" -}}
app.kubernetes.io/name: limen-{{ .component }}
app.kubernetes.io/instance: {{ .key }}
{{- end -}}

{{- define "limen.labels" -}}
{{ include "limen.selector" . }}
app.kubernetes.io/part-of: limen
{{- end -}}

{{- define "limen.pullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets: {{ toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* limen.merged: dict "defaults" map "over" map; returns YAML of defaults overridden by over. */}}
{{- define "limen.merged" -}}
{{- toYaml (mustMergeOverwrite (deepCopy .defaults) (deepCopy (.over | default dict))) -}}
{{- end -}}

{{/* limen.firstKey: the alphabetically first key of a map. */}}
{{- define "limen.firstKey" -}}
{{- required "define at least one group of the component this one dials" (keys . | sortAlpha | first) -}}
{{- end -}}
