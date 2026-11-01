[CmdletBinding()]
param([switch]$CheckOnly)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$config = Join-Path $PSScriptRoot '.env.cloud'
if (-not (Test-Path -LiteralPath $config)) { throw 'Cloud collector credentials are not configured in deploy/.env.cloud.' }
foreach ($line in [IO.File]::ReadAllLines($config)) {
    $parts = $line -split '=', 2
    if ($parts.Count -eq 2 -and $parts[0] -in @('LAB_SOC_URL', 'LAB_COLLECTOR_KEY')) {
        [Environment]::SetEnvironmentVariable($parts[0], $parts[1], 'Process')
    }
}
if (-not $env:LAB_SOC_URL -or -not $env:LAB_SOC_URL.StartsWith('https://') -or $env:LAB_COLLECTOR_KEY.Length -lt 24) { throw 'Valid HTTPS origin and collector key required.' }
$python = Join-Path $root '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Project .venv interpreter is missing.' }
if ($CheckOnly) { Write-Host 'Cloud collector configuration is valid. Credentials were not printed.'; return }
Set-Location -LiteralPath $root
Write-Host 'Forwarding only deploy/logs/auth.log and deploy/logs/security.jsonl to the configured live SOC. Keys are not printed.'
& $python -m collectors.file_forwarder --file (Join-Path $PSScriptRoot 'logs/auth.log') --file (Join-Path $PSScriptRoot 'logs/security.jsonl') --state (Join-Path $PSScriptRoot 'cloud-collector.db')
exit $LASTEXITCODE
