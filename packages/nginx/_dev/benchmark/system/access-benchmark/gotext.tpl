{{- $timestamp := generate "timestamp" -}}
{{- $remoteIp := generate "remote_ip" -}}
{{- $remoteUser := generate "remote_user" -}}
{{- $requestMethod := generate "request_method" -}}
{{- $requestPath := generate "request_path" -}}
{{- $statusCode := generate "status_code" -}}
{{- $responseBytes := generate "response_bytes" -}}
{{- $userAgent := generate "user_agent" -}}
{{$remoteIp}} - {{$remoteUser}} [{{$timestamp.Format "02/Jan/2006:15:04:05"}} +0000] "{{$requestMethod}} {{$requestPath}} HTTP/1.1" {{$statusCode}} {{$responseBytes}} "-" "{{$userAgent}}"
