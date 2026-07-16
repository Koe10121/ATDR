[CmdletBinding()]
param(
    [string]$TemplateRoot,
    [switch]$DryRun,
    [switch]$NoBrowser
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

function Start-TrackedProcess {
    param(
        [string]$Name,
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string]$LogDirectory
    )
    $stdout = Join-Path $LogDirectory "$Name.out.log"
    $stderr = Join-Path $LogDirectory "$Name.err.log"
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -WorkingDirectory $WorkingDirectory -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    Start-Sleep -Milliseconds 200
    if ($process.HasExited) {
        throw "$Name stopped during startup. Check .atdr_runtime/logs/$Name.err.log."
    }
    return [pscustomobject]@{
        name = $Name
        pid = $process.Id
        started_at = $process.StartTime.ToUniversalTime().ToString("o")
        working_directory = $WorkingDirectory
    }
}

function Wait-ServiceReady {
    param([string]$Name, [string]$Url, [int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $result = Test-HttpEndpoint -Url $Url -TimeoutSeconds 2
        if ($result.reachable) { return }
        Start-Sleep -Seconds 1
    }
    throw "$Name did not become ready at $Url. Check .atdr_runtime/logs for the concise component error."
}

function Set-TemporaryEnvironment {
    param([hashtable]$Values)
    $original = @{}
    foreach ($name in $Values.Keys) {
        $original[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
        [Environment]::SetEnvironmentVariable($name, [string]$Values[$name], "Process")
    }
    return $original
}

function Restore-TemporaryEnvironment {
    param([hashtable]$Original)
    foreach ($name in $Original.Keys) {
        [Environment]::SetEnvironmentVariable($name, $Original[$name], "Process")
    }
}

$started = [System.Collections.Generic.List[object]]::new()
try {
    $root = Get-AtdrProjectRoot
    $template = Resolve-TemplateRoot $TemplateRoot
    $structure = Test-TemplateShellStructure $template
    if (-not $structure.valid) { throw "MFU shell is incomplete. Missing: $($structure.missing -join ', ')" }
    $teamConfig = Read-TeamConfig
    $shellDistributionMode = if ($null -ne $teamConfig -and $teamConfig.PSObject.Properties.Name -contains "shell_distribution_mode") { [string]$teamConfig.shell_distribution_mode } else { "approved_directory" }
    $packageStatus = Get-InstalledMfuShellPackageStatus $template
    if ($shellDistributionMode -eq "versioned_package" -and (-not $packageStatus.managed -or -not $packageStatus.valid)) {
        throw "Versioned MFU shell integrity check failed ($($packageStatus.diagnosis)). Rerun setup with the approved package."
    }

    $runtime = Get-AtdrRuntimeDirectory
    $metadataPath = Join-Path $runtime "system-processes.json"
    if (Test-Path -LiteralPath $metadataPath) {
        $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
        $active = @($metadata.processes | Where-Object { Get-Process -Id $_.pid -ErrorAction SilentlyContinue })
        if ($active.Count) { throw "ATDR system processes are already running. Use .\scripts\check_system.ps1 or .\scripts\stop_system.ps1." }
        Remove-Item -LiteralPath $metadataPath -Force
    }

    $envPath = Join-Path $root ".env"
    $envValues = Read-DotEnvFile $envPath
    $missingAuth = @(Get-MissingShellAuthFields $envValues)
    if ($missingAuth.Count) { throw "Shell authentication configuration is incomplete. Run setup again. Missing: $($missingAuth -join ', ')" }
    if (-not $envValues.Contains("RESPONSE_SIMULATION") -or ([string]$envValues["RESPONSE_SIMULATION"]).ToLowerInvariant() -ne "true") {
        throw "RESPONSE_SIMULATION must remain true before the system can start."
    }

    $shellEnvPath = Join-Path $template "backend-node\.env.local"
    $shellValues = Read-DotEnvFile $shellEnvPath
    $shellFrontendEnvPath = Join-Path $template "frontend-vue\.env.localdev"
    $shellFrontendValues = Read-DotEnvFile $shellFrontendEnvPath
    $missingProvider = @(Get-MissingTemplateProviderFields $shellValues)
    if ($missingProvider.Count) {
        throw "MFU shell private provider configuration is not installed ($($missingProvider.Count) required fields). Add the approved backend-node/.env.local outside Git, then run .\scripts\check_system.ps1 -Json for the missing field names."
    }
    $googleStatus = Get-TemplateGoogleClientStatus $template
    if (-not $googleStatus.ready) {
        throw "MFU Google authentication preflight failed ($($googleStatus.diagnosis)). $(Get-TemplateGoogleClientAction $googleStatus)"
    }
    if (-not (Test-TcpEndpoint -Port 27017)) {
        throw "MongoDB is unavailable at 127.0.0.1:27017. Start MongoDB for the MFU shell; ATDR itself continues to use SQLAlchemy/SQLite or PostgreSQL."
    }

    $python = Join-Path $root ".venv\Scripts\python.exe"
    $node = Get-CommandPathSafe "node"
    if (-not (Test-Path -LiteralPath $python)) { throw "Python virtual environment is missing. Run .\scripts\setup_team.ps1 first." }
    if (-not $node) { throw "Node.js is missing. Install Node.js 20.19 or newer and rerun setup." }
    $nodeVersion = & $node --version
    if (-not (Test-NodeVersionSupported $nodeVersion)) {
        throw "Node.js 20.19 or newer is required. Detected: $nodeVersion"
    }

    $reactCli = Join-Path $root "frontend\node_modules\vite\bin\vite.js"
    $vueCli = Join-Path $template "frontend-vue\node_modules\@vue\cli-service\bin\vue-cli-service.js"
    if (-not (Test-Path -LiteralPath $reactCli)) { throw "ATDR frontend dependencies are missing. Run setup_team.ps1." }
    if (-not (Test-Path -LiteralPath $vueCli)) { throw "MFU shell frontend dependencies are missing. Run setup_team.ps1." }

    $ports = [ordered]@{ atdr_backend = 8000; atdr_frontend = 5173; shell_backend = 8214; shell_frontend = 8080 }
    $occupied = @($ports.GetEnumerator() | Where-Object { Test-TcpEndpoint -Port $_.Value } | ForEach-Object { "$($_.Key):$($_.Value)" })
    if ($occupied.Count) { throw "Required port(s) are already occupied: $($occupied -join ', '). Stop the owning service or configure a free team profile." }

    Write-Host "ATDR system startup preflight passed." -ForegroundColor Green
    Write-Host "  Entry point: http://localhost:8080/#/pages/login"
    Write-Host "  Authentication: template_shell"
    Write-Host "  Shell distribution: $shellDistributionMode$(if ($packageStatus.valid) { " / $($packageStatus.release_version) verified" } else { '' })"
    Write-Host "  MFU IAM proxy: configured (account acceptance still requires a real sign-in)"
    Write-Host "  Google OAuth client agreement: verified"
    Write-Host "  Response simulation: true"
    if ($DryRun) {
        Write-Host "Dry run complete. No process was started and no browser was opened." -ForegroundColor Cyan
        exit 0
    }

    $logDir = Join-Path $runtime "logs"
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null

    $started.Add((Start-TrackedProcess -Name "atdr-backend" -FilePath $python -Arguments @("-m", "uvicorn", "atdr.app.main:app", "--host", "127.0.0.1", "--port", "8000") -WorkingDirectory $root -LogDirectory $logDir))
    $started.Add((Start-TrackedProcess -Name "atdr-frontend" -FilePath $node -Arguments @("node_modules/vite/bin/vite.js", "--host", "127.0.0.1", "--port", "5173", "--strictPort") -WorkingDirectory (Join-Path $root "frontend") -LogDirectory $logDir))

    $shellBackendEnvironment = @{
        DOTENV_CONFIG_PATH = $shellEnvPath
        KEY = [string]$envValues["MFU_SHELL_LOCAL_KEY"]
        PORT = "8214"
        BASE_SERVER_URL = "http://127.0.0.1:8214"
        ATDR_HANDOFF_ENABLED = "true"
        ATDR_HANDOFF_SHARED_SECRET = [string]$envValues["MFU_IAM_HANDOFF_SHARED_SECRET"]
        ATDR_HANDOFF_SECRET_HEADER = "x-atdr-handoff-secret"
        ATDR_HANDOFF_CONSUME_URL = "http://127.0.0.1:8000/api/auth/mfu-iam/handoff/consume"
        ATDR_HANDOFF_ALLOWED_RETURN_PATHS = "/overview,/alerts,/logs,/assistant,/response,/audit,/ml"
        ATDR_HANDOFF_ALLOWED_DOMAINS = [string]$envValues["MFU_IAM_ALLOWED_DOMAINS"]
        GOOGLE_CLIENT_ID = [string]$shellValues["GOOGLE_CLIENT_ID"]
    }
    $original = Set-TemporaryEnvironment $shellBackendEnvironment
    try {
        $started.Add((Start-TrackedProcess -Name "shell-backend" -FilePath $node -Arguments @("-r", "dotenv/config", "server.js") -WorkingDirectory (Join-Path $template "backend-node") -LogDirectory $logDir))
    }
    finally { Restore-TemporaryEnvironment $original }

    $shellFrontendEnvironment = @{
        PORT = "8080"
        BROWSER = "none"
        VUE_APP_API_BASE_URL = "http://127.0.0.1:8214"
        VUE_APP_SOCKET_URL = "http://127.0.0.1:8214"
        VUE_APP_BASE_URL = "http://localhost:8080"
        VUE_APP_ATDR_HANDOFF_CONSUME_URL = "http://127.0.0.1:8000/api/auth/mfu-iam/handoff/consume"
        VUE_APP_CLIENTID = [string]$shellFrontendValues["VUE_APP_CLIENTID"]
    }
    $original = Set-TemporaryEnvironment $shellFrontendEnvironment
    try {
        $started.Add((Start-TrackedProcess -Name "shell-frontend" -FilePath $node -Arguments @("node_modules/@vue/cli-service/bin/vue-cli-service.js", "serve", "--mode", "localdev", "--host", "127.0.0.1", "--port", "8080") -WorkingDirectory (Join-Path $template "frontend-vue") -LogDirectory $logDir))
    }
    finally { Restore-TemporaryEnvironment $original }

    [ordered]@{
        version = 1
        started_at = (Get-Date).ToUniversalTime().ToString("o")
        processes = @($started)
        secrets_stored = $false
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8

    Wait-ServiceReady "ATDR backend" "http://127.0.0.1:8000/health/live"
    Wait-ServiceReady "ATDR frontend" "http://127.0.0.1:5173"
    Wait-ServiceReady -Name "MFU shell backend" -Url "http://127.0.0.1:8214/healthz" -TimeoutSeconds 90
    # The supervisor's legacy Vue/Webpack shell can need several minutes for
    # its first cold compile on a teammate machine.
    Wait-ServiceReady -Name "MFU shell frontend" -Url "http://127.0.0.1:8080" -TimeoutSeconds 240

    Write-Host "All components are ready." -ForegroundColor Green
    Write-Host "  MFU sign in: http://localhost:8080/#/pages/login"
    Write-Host "  ATDR API: http://127.0.0.1:8000"
    Write-Host "  ATDR React: http://127.0.0.1:5173 (entered through secure shell handoff)"
    if (-not $NoBrowser) { Start-Process "http://localhost:8080/#/pages/login" | Out-Null }
}
catch {
    $startedRecords = @($started)
    [array]::Reverse($startedRecords)
    foreach ($record in $startedRecords) {
        Stop-Process -Id $record.pid -Force -ErrorAction SilentlyContinue
    }
    $metadataPath = Join-Path (Get-AtdrRuntimeDirectory) "system-processes.json"
    if (Test-Path -LiteralPath $metadataPath) { Remove-Item -LiteralPath $metadataPath -Force }
    [Console]::Error.WriteLine("ATDR startup failed: $($_.Exception.Message)")
    exit 1
}
