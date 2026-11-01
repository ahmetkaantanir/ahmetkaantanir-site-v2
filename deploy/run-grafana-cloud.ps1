[CmdletBinding()]
param([switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
$config = Join-Path $PSScriptRoot '.env.grafana'
if (-not (Test-Path -LiteralPath $config)) { throw 'Grafana Cloud credentials are missing from deploy/.env.grafana.' }
foreach ($line in [IO.File]::ReadAllLines($config)) {
    $parts = $line -split '=', 2
    if ($parts.Count -eq 2 -and $parts[0] -in @('LAB_LOKI_PUSH_URL', 'LAB_LOKI_WRITE_USER', 'LAB_LOKI_WRITE_TOKEN')) {
        [Environment]::SetEnvironmentVariable($parts[0], $parts[1], 'Process')
    }
}
$uri = $null
if (-not [Uri]::TryCreate($env:LAB_LOKI_PUSH_URL, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/loki/api/v1/push') {
    throw 'A Grafana Cloud HTTPS Loki push endpoint is required.'
}
if (-not $env:LAB_LOKI_WRITE_USER -or -not $env:LAB_LOKI_WRITE_TOKEN) { throw 'Write-only Loki username and access token are required.' }
$binary = Join-Path $PSScriptRoot 'runtime/alloy-windows-amd64.exe'
if (-not (Test-Path -LiteralPath $binary)) { throw 'The verified Alloy Windows binary is missing from deploy/runtime.' }
$logDir = Join-Path $PSScriptRoot 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
foreach ($file in @('auth.log','security.jsonl')) {
    $path = Join-Path $logDir $file
    if (-not (Test-Path -LiteralPath $path)) { [IO.File]::WriteAllText($path, '') }
}
$env:LAB_AUTH_LOG = (Join-Path $logDir 'auth.log').Replace('\','/')
$env:LAB_SECURITY_LOG = (Join-Path $logDir 'security.jsonl').Replace('\','/')
$alloyConfig = Join-Path $PSScriptRoot 'config.cloud.alloy'
if ($ValidateOnly) {
    & $binary validate $alloyConfig
} else {
    Write-Host 'Sending only deploy/logs/auth.log and deploy/logs/security.jsonl to configured Grafana Cloud. Credentials are not printed.'
    $state = Join-Path $PSScriptRoot 'runtime/alloy-state'
    & $binary run --server.http.listen-addr=127.0.0.1:12345 "--storage.path=$state" $alloyConfig
}
exit $LASTEXITCODE
