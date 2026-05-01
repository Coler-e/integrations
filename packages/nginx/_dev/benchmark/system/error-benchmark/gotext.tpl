{{- $timestamp := generate "timestamp" -}}
{{- $logLevel := generate "log_level" -}}
{{- $pid := generate "pid" -}}
{{- $tid := generate "tid" -}}
{{- $cid := generate "cid" -}}
{{- $requestPath := generate "request_path" -}}
{{- $clientIp := generate "client_ip" -}}
{{- $serverName := generate "server_name" -}}
{{- $requestMethod := generate "request_method" -}}
{{$timestamp.Format "2006/01/02 15:04:05"}} [{{$logLevel}}] {{$pid}}#{{$tid}}: *{{$cid}} open() "/usr/share/nginx/html{{$requestPath}}" failed (2: No such file or directory), client: {{$clientIp}}, server: {{$serverName}}, request: "{{$requestMethod}} {{$requestPath}} HTTP/1.1", host: "{{$serverName}}:80"
