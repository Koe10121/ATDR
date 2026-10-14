[CmdletBinding()]
param(
    [string]$TemplateRoot,
    [switch]$DryRun,
    [switch]$NoBrowser,
    # Start only these parts beside the ones already running. scripts\watch_system.ps1 uses it to bring back a
    # part that stopped; a person starts ATDR without it.
    [string[]]$Only = @(),
    # Start this folder's own copy although ATDR runs from a live copy elsewhere (scripts\release.cmd).
    [switch]$Development,
    # Given by the watcher when a release asks it to start ATDR: the release is the one start that may run while
    # the release itself is on record as unfinished.
    [switch]$DuringRelease,
    # Given by the watcher with every start it makes. Where ATDR runs without a sign-in
    # (scripts\autostart.cmd -BeforeSignIn) a start without it is handed to the watcher.
    [switch]$ByWatcher
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
# With -Only: the parts that are running and stay as they are.
$kept = @()
# Given through -File, a list of names arrives as one text with commas.
$Only = @($Only | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$partial = @($Only).Count -gt 0
$locked = $false
# Whether this run has looked at the record of running parts (system-processes.json) and so knows what is on it.
# A start that is refused before that must leave the record exactly as it is.
$recordRead = $false
try {
    $root = Get-AtdrProjectRoot
    $runtime = Get-AtdrRuntimeDirectory
    $metadataPath = Join-Path $runtime "system-processes.json"
    # Only a version that was committed and checked runs live: the folder ATDR is developed in is not started by
    # accident, and a folder a release left half changed is not started at all.
    $liveCopy = Get-AtdrLiveCopy
    if ($liveCopy -and -not $Development) {
        throw "This is the folder ATDR is developed in; ATDR runs from $liveCopy. Start it there ($liveCopy\scripts\start_system.cmd), or put a new version there with .\scripts\release.cmd go. To start this folder's own copy anyway, add -Development."
    }
    $unfinished = Get-AtdrUnfinishedRelease
    if ($null -ne $unfinished -and -not $DuringRelease) {
        $began = if ($null -ne $unfinished.started_at) { " (it began $($unfinished.started_at.ToLocalTime().ToString('yyyy-MM-dd HH:mm')))" } else { "" }
        if ($unfinished.under_way) {
            throw "A release into this folder is under way$began. It stops and starts ATDR itself, and puts the version before back when the new one does not come up; nothing was started."
        }
        $where = if ($unfinished.source) { " in $($unfinished.source)" } else { " in the folder ATDR is developed in" }
        throw "A release into this folder did not finish$began, so its files may be half of one version and half of another. Run .\scripts\release.cmd recover$where; it puts back the version that was running."
    }
    if ((Test-AtdrRunsWithoutSignIn) -and -not $ByWatcher -and -not $partial -and -not $DryRun) {
        # Where ATDR runs without a sign-in, its parts belong to the watcher's task. Started from this window they
        # would belong to this sign-in and end with it, so the start is handed to the watcher.
        Write-Host "ATDR runs here whether or not anyone is signed in, so its watcher makes the start. Asking it now; this can take a minute or two." -ForegroundColor Cyan
        if (-not (Test-AtdrWatcherAlive) -and -not (Start-AtdrWatcherTask)) {
            throw "The watcher (the task '$AtdrWatcherTaskName') is not running and could not be started from this window. Windows starts it by itself within a minute; run this again then."
        }
        $answer = Request-AtdrStart -By "start_system"
        if ($null -eq $answer) { throw "The watcher did not answer within eight minutes. Its log: .atdr_runtime\logs\watch.log" }
        if (-not $answer.ok) { throw ([string]$answer.said -replace '^ATDR startup failed: ', '') }
        $asked = @($answer.asked_for | Where-Object { $_ })
        Write-Host "ATDR is running: its watcher started $(if ($asked.Count) { $asked -join ', ' } else { 'nothing, because every part was running already' })." -ForegroundColor Green
        Write-Host "  MFU sign in: http://localhost:8080/#/pages/login"
        Write-Host "  Status: .\scripts\check_system.cmd -RequireReady"
        Write-Host "  Stop: .\scripts\stop_system.cmd"
        if (-not $NoBrowser) { Start-Process "http://localhost:8080/#/pages/login" | Out-Null }
        exit 0
    }
    if (-not $DryRun) {
        # The sign-in start and the watcher must not launch the same parts at the same moment.
        $locked = Enter-AtdrStartLock
        if (-not $locked) {
            Write-Host "ATDR is being started by another process just now. Status: .\scripts\check_system.cmd"
            exit 3
        }
    }
    if ($partial -and (Read-AtdrDesiredState).state -ne "running") {
        # stop_system ran while the watcher was about to bring a part back.
        Write-Host "ATDR is not meant to be running (it was stopped with stop_system). Nothing was started."
        Exit-AtdrStartLock
        exit 0
    }
    $recordRead = $true
    if ($partial -and (Test-Path -LiteralPath $metadataPath)) {
        $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
        $kept = @(@($metadata.processes) | Where-Object { Test-TrackedProcessRecordActive $_ })
        $Only = @($Only | Where-Object { $_ -notin @($kept | ForEach-Object { [string]$_.name }) })
        if (-not $Only.Count) {
            Write-Host "Those parts are already running. Nothing was started."
            Exit-AtdrStartLock
            exit 0
        }
    }
    elseif (Test-Path -LiteralPath $metadataPath) {
        $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
        $records = @($metadata.processes)
        $active = @($records | Where-Object { Test-TrackedProcessRecordActive $_ })
        if ($active.Count) {
            $serviceReadiness = @{
                atdr_backend = (Test-HttpEndpoint "http://127.0.0.1:8000/health/live").reachable
                atdr_frontend = (Test-HttpEndpoint "http://127.0.0.1:5173").reachable
                shell_backend = (Test-HttpEndpoint "http://127.0.0.1:8214/healthz").reachable
                shell_frontend = (Test-HttpEndpoint -Url "http://localhost:8080" -TimeoutSeconds 10).reachable
            }
            $runtimeState = Get-TrackedSystemRuntimeClassification `
                -TrackedNames @($records | ForEach-Object { [string]$_.name }) `
                -ActiveNames @($active | ForEach-Object { [string]$_.name }) `
                -ServiceReadiness $serviceReadiness
            if ($runtimeState.state -eq "healthy") {
                Write-Host "ATDR is already running and all four components are healthy." -ForegroundColor Green
                Write-Host "  MFU sign in: http://localhost:8080/#/pages/login"
                Write-Host "  Status: .\scripts\check_system.cmd -RequireReady"
                Write-Host "  Stop: .\scripts\stop_system.cmd"
                $runningEnv = Read-DotEnvFile (Join-Path $root ".env")
                $assistantModel = try {
                    if ($DryRun) { Get-AssistantModelStatus $runningEnv } else { Start-AssistantModelIfStopped $runningEnv }
                } catch { [pscustomobject]@{ engine = "ollama"; state = "not_running"; model = "" } }
                Write-Host "  SOC Assistant model: $(Get-AssistantModelSummary $assistantModel)" -ForegroundColor $(if ($assistantModel.state -in @('not_running', 'model_missing')) { 'Yellow' } else { 'Gray' })
                if (-not $DryRun) {
                    Set-AtdrDesiredState -State "running" -By "start_system"
                    [void](Start-AtdrWatcherTask)
                    Exit-AtdrStartLock
                }
                if (-not $NoBrowser -and -not $DryRun) { Start-Process "http://localhost:8080/#/pages/login" | Out-Null }
                exit 0
            }
            # The parts that are running stay on record: without it stop_system could no longer find them.
            $kept = $active
            throw "ATDR has a partial or unhealthy launcher-managed runtime ($($runtimeState.active_count)/4 processes, $($runtimeState.ready_count)/4 services ready). The watcher (.\scripts\autostart.cmd) brings back a part that stopped within a minute. To start over: .\scripts\check_system.cmd -Json, then .\scripts\stop_system.cmd."
        }
        Remove-Item -LiteralPath $metadataPath -Force
    }

    $template = Resolve-TemplateRoot $TemplateRoot
    $structure = Test-TemplateShellStructure $template
    if (-not $structure.valid) { throw "MFU shell is incomplete. Missing: $($structure.missing -join ', ')" }
    $teamConfig = Read-TeamConfig
    $shellDistributionMode = if ($null -ne $teamConfig -and $teamConfig.PSObject.Properties.Name -contains "shell_distribution_mode") { [string]$teamConfig.shell_distribution_mode } else { "approved_directory" }
    $packageStatus = Get-InstalledMfuShellPackageStatus $template
    if ($shellDistributionMode -eq "versioned_package" -and (-not $packageStatus.managed -or -not $packageStatus.valid)) {
        throw "Versioned MFU shell integrity check failed ($($packageStatus.diagnosis)). Rerun setup with the approved package."
    }

    $envPath = Join-Path $root ".env"
    $envValues = Read-DotEnvFile $envPath
    $missingAuth = @(Get-MissingShellAuthFields $envValues)
    if ($missingAuth.Count) { throw "Shell authentication configuration is incomplete. Run .\scripts\setup_team.cmd again. Missing: $($missingAuth -join ', ')" }
    if (-not $envValues.Contains("RESPONSE_SIMULATION") -or ([string]$envValues["RESPONSE_SIMULATION"]).ToLowerInvariant() -ne "true") {
        throw "RESPONSE_SIMULATION must remain true before the system can start."
    }

    $shellEnvPath = Join-Path $template "backend-node\.env.local"
    $shellValues = Read-DotEnvFile $shellEnvPath
    $shellFrontendEnvPath = Join-Path $template "frontend-vue\.env.localdev"
    $shellFrontendValues = Read-DotEnvFile $shellFrontendEnvPath
    $missingProvider = @(Get-MissingTemplateProviderFields $shellValues)
    if ($missingProvider.Count) {
        throw "MFU shell private provider configuration is not installed ($($missingProvider.Count) required fields). Add the approved backend-node/.env.local outside Git, then run .\scripts\check_system.cmd -Json for the missing field names."
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
    if (-not (Test-Path -LiteralPath $python)) { throw "Python virtual environment is missing. Run .\scripts\setup_team.cmd first." }
    if (-not $node) { throw "Node.js is missing. Install Node.js 20.19 or newer and rerun setup." }
    $nodeVersion = & $node --version
    if (-not (Test-NodeVersionSupported $nodeVersion)) {
        throw "Node.js 20.19 or newer is required. Detected: $nodeVersion"
    }

    $reactCli = Join-Path $root "frontend\node_modules\vite\bin\vite.js"
    $vueCli = Join-Path $template "frontend-vue\node_modules\@vue\cli-service\bin\vue-cli-service.js"
    # The dashboard is served from its built files, so the tools that build it are needed only where there is no
    # build yet. Without them a changed source is not built (the build step below says so) and the last build is served.
    $dashboardBuilt = Test-Path -LiteralPath (Join-Path $root "frontend\dist\index.html") -PathType Leaf
    if (-not (Test-Path -LiteralPath $reactCli) -and -not $dashboardBuilt) { throw "ATDR frontend dependencies are missing. Run .\scripts\setup_team.cmd." }
    if (-not (Test-Path -LiteralPath $vueCli)) { throw "MFU shell frontend dependencies are missing. Run .\scripts\setup_team.cmd." }

    # What this run starts: every part ATDR is set up to run, or with -Only the parts named.
    $wanted = if ($partial) { @($Only) } else { @(Get-AtdrExpectedParts $envValues) }
    $unknown = @($wanted | Where-Object { $_ -notin @("atdr-backend", "atdr-worker", "atdr-syslog", "atdr-frontend", "shell-backend", "shell-frontend") })
    if ($unknown.Count) { throw "Unknown part(s): $($unknown -join ', ')." }
    $ports = [ordered]@{}
    foreach ($pair in @(@("atdr-backend", "atdr_backend", 8000), @("atdr-frontend", "atdr_frontend", 5173), @("shell-backend", "shell_backend", 8214), @("shell-frontend", "shell_frontend", 8080))) {
        if ($pair[0] -in $wanted) { $ports[$pair[1]] = $pair[2] }
    }
    $occupied = @($ports.GetEnumerator() | Where-Object { Test-TcpEndpoint -Port $_.Value } | ForEach-Object { "$($_.Key):$($_.Value)" })
    if ($occupied.Count) { throw "Required port(s) are already occupied: $($occupied -join ', '). Stop the owning service or configure a free team profile." }

    Write-Host "ATDR system startup preflight passed." -ForegroundColor Green
    Write-Host "  Entry point: http://localhost:8080/#/pages/login"
    Write-Host "  Authentication: template_shell"
    Write-Host "  Shell distribution: $shellDistributionMode$(if ($packageStatus.valid) { " / $($packageStatus.release_version) verified" } else { '' })"
    Write-Host "  MFU IAM proxy: configured (account acceptance still requires a real sign-in)"
    Write-Host "  Google OAuth client agreement: verified"
    Write-Host "  Response simulation: true"
    $workerEnabled = $envValues.Contains("OPERATION_WORKER_ENABLED") -and ([string]$envValues["OPERATION_WORKER_ENABLED"]).ToLowerInvariant() -eq "true"
    $autoDetection = $envValues.Contains("AUTO_DETECTION_ENABLED") -and ([string]$envValues["AUTO_DETECTION_ENABLED"]).ToLowerInvariant() -eq "true"
    if ($workerEnabled) {
        Write-Host "  Background worker: on (runs queued imports)"
    } else {
        Write-Host "  Background worker: off (set OPERATION_WORKER_ENABLED=true in .env to run queued imports)"
    }
    if ($autoDetection -and $workerEnabled) {
        Write-Host "  Automatic detection: on (the worker checks new logs by itself)"
    } elseif ($autoDetection) {
        Write-Host "  Automatic detection: on, but the background worker is off, so nothing is checked by itself" -ForegroundColor Yellow
    } else {
        Write-Host "  Automatic detection: off (new logs wait for Check all unchecked logs)"
    }
    $syslogEnabled = $envValues.Contains("SYSLOG_ENABLED") -and ([string]$envValues["SYSLOG_ENABLED"]).ToLowerInvariant() -eq "true"
    if ($syslogEnabled) {
        $syslogHost = if ($envValues.Contains("SYSLOG_HOST") -and [string]$envValues["SYSLOG_HOST"]) { [string]$envValues["SYSLOG_HOST"] } else { "127.0.0.1" }
        $syslogPort = if ($envValues.Contains("SYSLOG_PORT") -and [string]$envValues["SYSLOG_PORT"]) { [string]$envValues["SYSLOG_PORT"] } else { "5514" }
        Write-Host "  Live syslog: on (receives firewall logs on UDP $($syslogHost):$syslogPort)"
    } else {
        Write-Host "  Live syslog: off (set SYSLOG_ENABLED=true in .env to receive firewall logs)"
    }
    $modelPathValue = if ($envValues.Contains("ML_MODEL_PATH") -and [string]$envValues["ML_MODEL_PATH"]) {
        [string]$envValues["ML_MODEL_PATH"]
    } else {
        "atdr/models/isolation_forest.joblib"
    }
    $modelPath = if ([System.IO.Path]::IsPathRooted($modelPathValue)) {
        $modelPathValue
    } else {
        Join-Path $root $modelPathValue
    }
    if (Test-Path -LiteralPath $modelPath -PathType Leaf) {
        Write-Host "  Advisory anomaly model available (decision support only; threat accuracy not validated)"
    } else {
        Write-Host "  Advisory anomaly model unavailable" -ForegroundColor Yellow
        Write-Host "    Preflight: .\scripts\bootstrap_advisory_anomaly.cmd -UseCommittedSyntheticSample"
    }
    if ($DryRun) {
        Write-Host "Dry run complete. No process was started and no browser was opened." -ForegroundColor Cyan
        exit 0
    }

    if ($partial) {
        Write-Host "Starting: $($wanted -join ', ')." -ForegroundColor Cyan
    }
    else {
        Write-Host "Starting all four components. Wait for 'All components are ready' before opening the browser." -ForegroundColor Cyan
        Write-Host "  The MFU shell may need 20-60 seconds for its first compile."
    }

    $logDir = Join-Path $runtime "logs"
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null

    if ("atdr-backend" -in $wanted) {
        $started.Add((Start-TrackedProcess -Name "atdr-backend" -FilePath $python -Arguments @("-m", "uvicorn", "atdr.app.main:app", "--host", "127.0.0.1", "--port", "8000") -WorkingDirectory $root -LogDirectory $logDir))
    }
    if ($workerEnabled) {
        # Runs queued imports and jobs (Validation Controls > Queue import).
        # Optional: ATDR still works without it, so a failed start only warns.
        try {
            if ("atdr-worker" -in $wanted) {
                $started.Add((Start-TrackedProcess -Name "atdr-worker" -FilePath $python -Arguments @("-m", "atdr.scripts.run_operation_worker", "--watch") -WorkingDirectory $root -LogDirectory $logDir))
            }
        }
        catch {
            Write-Warning "Background worker did not start ($($_.Exception.Message)). ATDR runs without it; queued imports wait until it runs."
            # Asked for by name, it is the whole of this run: the watcher has to know it did not come back.
            if ($partial) { throw }
        }
    }
    if ($syslogEnabled) {
        # Receives the firewall's logs over UDP syslog. Optional like the worker: a failed start only warns.
        try {
            if ("atdr-syslog" -in $wanted) {
                $started.Add((Start-TrackedProcess -Name "atdr-syslog" -FilePath $python -Arguments @("-m", "atdr.scripts.run_syslog_receiver") -WorkingDirectory $root -LogDirectory $logDir))
            }
        }
        catch {
            Write-Warning "Live syslog receiver did not start ($($_.Exception.Message)). Firewall logs sent now are not received."
            if ($partial) { throw }
        }
    }
    if ("atdr-frontend" -in $wanted) {
        # The dashboard is served from its built files. They are built here when the source is newer than the
        # build; a build that fails leaves the last good one in place, and then only a warning is due.
        $buildOut = Join-Path $logDir "dashboard-build.out.log"
        $buildErr = Join-Path $logDir "dashboard-build.err.log"
        $build = Start-Process -FilePath $python -ArgumentList @("-m", "atdr.scripts.build_dashboard") -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $buildOut -RedirectStandardError $buildErr -PassThru
        $null = $build.Handle
        $build.WaitForExit()
        $buildSaid = if (Test-Path -LiteralPath $buildOut) { ((Get-Content -LiteralPath $buildOut -Raw -ErrorAction SilentlyContinue) + "").Trim() } else { "" }
        if ($build.ExitCode -ne 0) {
            throw "The dashboard has no build to serve ($buildSaid). See .atdr_runtime\logs\dashboard-build.err.log."
        }
        Write-Host "  Dashboard: $buildSaid" -ForegroundColor $(if ($buildSaid -match 'FAILED|not found') { 'Yellow' } else { 'Gray' })
        $started.Add((Start-TrackedProcess -Name "atdr-frontend" -FilePath $python -Arguments @("-m", "atdr.scripts.serve_dashboard", "--host", "127.0.0.1", "--port", "5173") -WorkingDirectory $root -LogDirectory $logDir))
    }

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
    if ("shell-backend" -in $wanted) {
        $original = Set-TemporaryEnvironment $shellBackendEnvironment
        try {
            $started.Add((Start-TrackedProcess -Name "shell-backend" -FilePath $node -Arguments @("-r", "dotenv/config", "server.js") -WorkingDirectory (Join-Path $template "backend-node") -LogDirectory $logDir))
        }
        finally { Restore-TemporaryEnvironment $original }
    }

    $shellFrontendEnvironment = @{
        PORT = "8080"
        BROWSER = "none"
        VUE_APP_API_BASE_URL = "http://127.0.0.1:8214"
        VUE_APP_SOCKET_URL = "http://127.0.0.1:8214"
        VUE_APP_BASE_URL = "http://localhost:8080"
        VUE_APP_ATDR_HANDOFF_CONSUME_URL = "http://127.0.0.1:8000/api/auth/mfu-iam/handoff/consume"
        VUE_APP_CLIENTID = [string]$shellFrontendValues["VUE_APP_CLIENTID"]
    }
    if ("shell-frontend" -in $wanted) {
        $original = Set-TemporaryEnvironment $shellFrontendEnvironment
        try {
            $started.Add((Start-TrackedProcess -Name "shell-frontend" -FilePath $node -Arguments @("node_modules/@vue/cli-service/bin/vue-cli-service.js", "serve", "--mode", "localdev", "--host", "127.0.0.1", "--port", "8080") -WorkingDirectory (Join-Path $template "frontend-vue") -LogDirectory $logDir))
        }
        finally { Restore-TemporaryEnvironment $original }
    }

    [ordered]@{
        version = 1
        started_at = (Get-Date).ToUniversalTime().ToString("o")
        processes = @(@($kept) + @($started))
        secrets_stored = $false
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8

    $startedNames = @($started | ForEach-Object { [string]$_.name })
    if ("atdr-backend" -in $startedNames) { Wait-ServiceReady "ATDR backend" "http://127.0.0.1:8000/health/live" }
    if ("atdr-frontend" -in $startedNames) { Wait-ServiceReady "ATDR frontend" "http://127.0.0.1:5173" }
    if ("shell-backend" -in $startedNames) { Wait-ServiceReady -Name "MFU shell backend" -Url "http://127.0.0.1:8214/healthz" -TimeoutSeconds 90 }
    # The supervisor's legacy Vue/Webpack shell can need several minutes for
    # its first cold compile on a teammate machine.
    if ("shell-frontend" -in $startedNames) { Wait-ServiceReady -Name "MFU shell frontend" -Url "http://127.0.0.1:8080" -TimeoutSeconds 240 }

    if ($partial) {
        Write-Host "Started: $($startedNames -join ', ')." -ForegroundColor Green
        Exit-AtdrStartLock
        exit 0
    }

    # Optional: the SOC Assistant falls back to built-in answers without it, so this never fails startup.
    $assistantModel = try { Start-AssistantModelIfStopped $envValues } catch { [pscustomobject]@{ engine = "ollama"; state = "not_running"; model = "" } }

    # From here on ATDR is meant to be running: the watcher brings back a part that stops.
    Set-AtdrDesiredState -State "running" -By "start_system"
    [void](Start-AtdrWatcherTask)

    Write-Host "All components are ready." -ForegroundColor Green
    Write-Host "  MFU sign in: http://localhost:8080/#/pages/login"
    Write-Host "  ATDR API: http://127.0.0.1:8000"
    Write-Host "  ATDR React: http://127.0.0.1:5173 (entered through secure shell handoff)"
    Write-Host "  SOC Assistant model: $(Get-AssistantModelSummary $assistantModel)" -ForegroundColor $(if ($assistantModel.state -in @('not_running', 'model_missing')) { 'Yellow' } else { 'Gray' })
    Exit-AtdrStartLock
    if (-not $NoBrowser) { Start-Process "http://localhost:8080/#/pages/login" | Out-Null }
}
catch {
    $startedRecords = @($started)
    [array]::Reverse($startedRecords)
    foreach ($record in $startedRecords) {
        Stop-Process -Id $record.pid -Force -ErrorAction SilentlyContinue
    }
    $metadataPath = Join-Path (Get-AtdrRuntimeDirectory) "system-processes.json"
    if (-not $recordRead) {
        # Refused before it looked at what is running (the folder ATDR is developed in, a release that did not
        # finish): the record stays as it is. On 11 October 2026 such a refusal removed it while five parts ran,
        # and from then on nothing could see, stop or restart them.
    }
    elseif (@($kept).Count) {
        # The parts that were running before this try still are.
        [ordered]@{
            version = 1
            started_at = (Get-Date).ToUniversalTime().ToString("o")
            processes = @($kept)
            secrets_stored = $false
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
    }
    elseif (Test-Path -LiteralPath $metadataPath) { Remove-Item -LiteralPath $metadataPath -Force }
    if ($locked) { Exit-AtdrStartLock }
    [Console]::Error.WriteLine("ATDR startup failed: $($_.Exception.Message)")
    exit 1
}
