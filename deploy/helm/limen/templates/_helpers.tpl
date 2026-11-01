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

{{/* limen.merged: dict "defaults" map "over" map; returns YAML of defaults overridden by over, key by key
     and down through nested maps. A zero value in "over" (false, 0, "") wins, which Sprig's merge functions skip. */}}
{{- define "limen.merged" -}}
{{- $out := deepCopy .defaults -}}
{{- range $k, $v := (.over | default dict) -}}
{{- if and (kindIs "map" $v) (kindIs "map" (get $out $k)) -}}
{{- $_ := set $out $k (include "limen.merged" (dict "defaults" (get $out $k) "over" $v) | fromYaml) -}}
{{- else -}}
{{- $_ := set $out $k (deepCopy $v) -}}
{{- end -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/* limen.firstKey: the alphabetically first key of a map. */}}
{{- define "limen.firstKey" -}}
{{- required "define at least one group of the component this one dials" (keys . | sortAlpha | first) -}}
{{- end -}}

{{/* limen.minAvailable: the group's PodDisruptionBudget, never so high that a node cannot be drained.
     With n replicas at most n-1 can be required; one replica has no budget to give. */}}
{{- define "limen.minAvailable" -}}
{{- max 0 (min (int .pdb.minAvailable) (sub (int .replicas) 1)) -}}
{{- end -}}
