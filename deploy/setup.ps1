[CmdletBinding()]
param([switch]$PrepareOnly)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $PSScriptRoot '.env'
function New-LabSecret {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes); [Convert]::ToBase64String($bytes) } finally { $rng.Dispose() }
}
if (-not (Test-Path -LiteralPath $envFile)) {
    $settings = @(
        'LOG_LAB_API_KEY=' + (New-LabSecret)
        'LAB_COLLECTOR_KEY=' + (New-LabSecret)
        'GRAFANA_ADMIN_PASSWORD=' + (New-LabSecret)
        'LAB_GRAFANA_URL=http://127.0.0.1:3000'
    )
    [IO.File]::WriteAllLines($envFile, $settings, (New-Object Text.UTF8Encoding($false)))
    # Current Windows user only; keys are never printed or put into Git.
    if ($env:OS -eq 'Windows_NT') {
        $acl = Get-Acl -LiteralPath $envFile
        $acl.SetAccessRuleProtection($true, $false)
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')
        $acl.SetAccessRule($rule)
        Set-Acl -LiteralPath $envFile -AclObject $acl
    }
}
$logDir = Join-Path $PSScriptRoot 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
foreach ($name in @('auth.log', 'security.jsonl')) {
    $path = Join-Path $logDir $name
    if (-not (Test-Path -LiteralPath $path)) { [IO.File]::WriteAllText($path, '') }
}
Write-Host 'Local credentials prepared in deploy/.env (ignored by Git). Existing credentials preserved.'
if ($PrepareOnly) { return }
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    $candidates = @("$env:ProgramFiles/Docker/Docker/resources/bin/docker.exe", "$env:LOCALAPPDATA/Programs/DockerDesktop/resources/bin/docker.exe")
    $docker = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $docker) { throw 'Docker Desktop must be installed and started. Re-run this script after installation.' }
$dockerCommand = if ($docker -is [System.Management.Automation.CommandInfo]) { $docker.Source } else { $docker }
& $dockerCommand info --format '{{.ServerVersion}}'
if ($LASTEXITCODE -ne 0) { throw 'Docker Engine is not running. Start Docker Desktop and re-run.' }
$compose = Join-Path $PSScriptRoot 'compose.yaml'
& $dockerCommand compose --env-file $envFile -f $compose config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Compose configuration is invalid.' }
& $dockerCommand compose --env-file $envFile -f $compose up -d --build --wait --wait-timeout 180
if ($LASTEXITCODE -ne 0) { throw 'A service did not start. Inspect docker compose ps and logs.' }
Write-Host 'SOC: http://127.0.0.1:5000/soc#platform | Grafana: http://127.0.0.1:3000'
Write-Host 'Read deploy/.env locally for SOC owner key / Grafana admin password. Do not share these values.'
