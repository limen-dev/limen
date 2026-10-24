{{- define "limen.image" -}}
{{- $reg := .root.Values.image.registry -}}
{{- $tag := required "image.tag is required" .root.Values.image.tag -}}
{{- if $reg }}{{ $reg }}/{{ end }}limen-{{ .component }}:{{ $tag }}
{{- end -}}

{{- define "limen.labels" -}}
app.kubernetes.io/name: limen-{{ . }}
app.kubernetes.io/part-of: limen
{{- end -}}

{{- define "limen.selector" -}}
app.kubernetes.io/name: limen-{{ . }}
{{- end -}}

{{- define "limen.pullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets: {{ toYaml . | nindent 2 }}
{{- end }}
{{- end -}}
