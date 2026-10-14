Set-StrictMode -Version Latest

function Get-AtdrProjectRoot {
    return [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
}

function Get-AtdrRuntimeDirectory {
    $path = Join-Path (Get-AtdrProjectRoot) ".atdr_runtime"
    return $path
}

function Get-TeamConfigPath {
    return Join-Path (Get-AtdrRuntimeDirectory) "team-config.json"
}

function Get-TemplateShellContractPath {
    return Join-Path (Get-AtdrProjectRoot) "config\mfu-shell-contract.json"
}

function Read-TemplateShellContract {
    $path = Get-TemplateShellContractPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "MFU shell dependency contract is missing: config\mfu-shell-contract.json"
    }
    try {
        return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    }
    catch {
        throw "MFU shell dependency contract is invalid JSON."
    }
}

function Read-TeamConfig {
    $path = Get-TeamConfigPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return $null
    }
    try {
        return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    }
    catch {
        throw "Private team configuration is invalid. Run .\scripts\setup_team.cmd again."
    }
}

function Read-DotEnvFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $values = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $values
    }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $clean = $line.Trim()
        if (-not $clean -or $clean.StartsWith("#") -or -not $clean.Contains("=")) {
            continue
        }
        $parts = $clean.Split("=", 2)
        $name = $parts[0].Trim()
        $value = $parts[1].Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $values[$name] = $value
    }
    return $values
}

function Test-PlaceholderValue {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    return $Value -match '(?i)replace|change-this|example|placeholder|your-'
}

function Resolve-TemplateRoot {
    param([string]$TemplateRoot)

    if (-not [string]::IsNullOrWhiteSpace($TemplateRoot)) {
        return [System.IO.Path]::GetFullPath($TemplateRoot)
    }
    if (-not [string]::IsNullOrWhiteSpace($env:MFU_TEMPLATE_ROOT)) {
        return [System.IO.Path]::GetFullPath($env:MFU_TEMPLATE_ROOT)
    }
    $config = Read-TeamConfig
    if ($null -ne $config -and -not [string]::IsNullOrWhiteSpace([string]$config.template_root)) {
        return [System.IO.Path]::GetFullPath([string]$config.template_root)
    }
    throw "MFU supervisor shell path is not configured. Run .\scripts\setup_team.cmd -TemplateRoot <path>."
}

function Test-TemplateShellStructure {
    param([Parameter(Mandatory = $true)][string]$TemplateRoot)
    $contract = Read-TemplateShellContract
    $required = @($contract.required_paths | ForEach-Object { ([string]$_).Replace('/', '\') })
    $missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $TemplateRoot $_) -PathType Leaf) })
    return [pscustomobject]@{
        valid = ($missing.Count -eq 0)
        missing = $missing
        contract_version = [int]$contract.contract_version
        distribution_mode = [string]$contract.distribution_mode
        source_revision_status = [string]$contract.source_revision_status
        distribution_blocker = [string]$contract.distribution_blocker
    }
}

function Get-TemplateShellFingerprint {
    param([Parameter(Mandatory = $true)][string]$TemplateRoot)

    $contract = Read-TemplateShellContract
    $builder = [System.Text.StringBuilder]::new()
    foreach ($relative in @($contract.fingerprint_paths | Sort-Object)) {
        $normalized = ([string]$relative).Replace('/', '\')
        $path = Join-Path $TemplateRoot $normalized
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            continue
        }
        $fileHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        [void]$builder.AppendLine("$relative=$fileHash")
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Get-InstalledMfuShellPackageStatus {
    param([Parameter(Mandatory = $true)][string]$TemplateRoot)

    $manifestPath = Join-Path $TemplateRoot "mfu-shell-release.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return [pscustomobject]@{
            managed = $false
            valid = $false
            release_version = $null
            source_fingerprint = $null
            file_count = 0
            diagnosis = "package_manifest_missing"
            secrets_exposed = $false
        }
    }
    try {
        $contract = Read-TemplateShellContract
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ([int]$manifest.package_format_version -ne [int]$contract.package_release.format_version) {
            throw "package_format_mismatch"
        }
        if ([string]$manifest.release_version -ne [string]$contract.package_release.release_version) {
            throw "release_version_mismatch"
        }
        if ([string]$manifest.source_fingerprint -ne [string]$contract.package_release.source_fingerprint) {
            throw "source_fingerprint_mismatch"
        }
        foreach ($entry in @($manifest.files)) {
            $relative = ([string]$entry.path).Replace('/', '\')
            $target = Join-Path $TemplateRoot $relative
            if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
                throw "source_file_missing"
            }
            $actual = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne [string]$entry.sha256) {
                throw "source_integrity_failed"
            }
        }
        return [pscustomobject]@{
            managed = $true
            valid = $true
            release_version = [string]$manifest.release_version
            source_fingerprint = [string]$manifest.source_fingerprint
            file_count = @($manifest.files).Count
            diagnosis = "verified"
            secrets_exposed = $false
        }
    }
    catch {
        return [pscustomobject]@{
            managed = $true
            valid = $false
            release_version = $null
            source_fingerprint = $null
            file_count = 0
            diagnosis = [string]$_.Exception.Message
            secrets_exposed = $false
        }
    }
}

function Copy-MfuShellPrivateConfiguration {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )

    $contract = Read-TemplateShellContract
    $copied = [System.Collections.Generic.List[string]]::new()
    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($contract.provider_private_files)) {
        $relative = ([string]$item).Replace('/', '\')
        $source = Join-Path $SourceRoot $relative
        $destination = Join-Path $DestinationRoot $relative
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            $missing.Add([string]$item)
            continue
        }
        $parent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination -Force
        $copied.Add([string]$item)
    }
    return [pscustomobject]@{
        copied = @($copied)
        missing = @($missing)
        secrets_exposed = $false
    }
}

function Get-MfuProviderBlocker {
    param(
        [object[]]$MissingProviderFields,
        [Parameter(Mandatory = $true)]$GoogleStatus
    )

    if (@($MissingProviderFields).Count -gt 0) {
        return "Install the approved private MFU shell configuration, then rerun setup."
    }
    if (-not $GoogleStatus.ready) {
        return Get-TemplateGoogleClientAction $GoogleStatus
    }
    return $null
}

function Test-NodeVersionSupported {
    param([AllowNull()][string]$Version)
    if ([string]::IsNullOrWhiteSpace($Version) -or $Version -notmatch '^v?(\d+)\.(\d+)\.(\d+)') {
        return $false
    }
    $major = [int]$matches[1]
    $minor = [int]$matches[2]
    return ($major -gt 20) -or ($major -eq 20 -and $minor -ge 19)
}

function Test-PythonPip {
    param([Parameter(Mandatory = $true)][string]$PythonPath)
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) { return $false }
    try {
        & $PythonPath -m pip --version *> $null
        return $LASTEXITCODE -eq 0
    }
    catch {
        return $false
    }
}

function Test-TrackedProcessRecordActive {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [int]$StartToleranceSeconds = 5
    )

    try {
        $process = Get-Process -Id ([int]$Record.pid) -ErrorAction SilentlyContinue
        if ($null -eq $process -or [string]::IsNullOrWhiteSpace([string]$Record.started_at)) {
            return $false
        }
        $recorded = [datetime]::Parse([string]$Record.started_at).ToUniversalTime()
        $actual = $process.StartTime.ToUniversalTime()
        return [math]::Abs(($actual - $recorded).TotalSeconds) -le $StartToleranceSeconds
    }
    catch {
        return $false
    }
}

function Get-TrackedSystemRuntimeClassification {
    param(
        [string[]]$TrackedNames = @(),
        [string[]]$ActiveNames = @(),
        [hashtable]$ServiceReadiness = @{}
    )

    $expected = @("atdr-backend", "atdr-frontend", "shell-backend", "shell-frontend")
    # The background operation worker only runs when OPERATION_WORKER_ENABLED
    # is true, and the syslog receiver only when SYSLOG_ENABLED is true, so
    # they are tracked when present but never required.
    $optional = @("atdr-worker", "atdr-syslog")
    $tracked = @($TrackedNames | ForEach-Object { [string]$_ })
    $active = @($ActiveNames | ForEach-Object { [string]$_ })
    $unexpected = @($tracked | Where-Object { $_ -notin $expected -and $_ -notin $optional })
    $missingTracked = @($expected | Where-Object { $_ -notin $tracked })
    $missingActive = @($expected | Where-Object { $_ -notin $active })
    $readyCount = @($ServiceReadiness.Values | Where-Object { [bool]$_ }).Count

    $state = if ($active.Count -eq 0) {
        "stale"
    }
    elseif ($unexpected.Count -eq 0 -and $missingTracked.Count -eq 0 -and $missingActive.Count -eq 0 -and $readyCount -eq 4) {
        "healthy"
    }
    else {
        "partial"
    }

    return [pscustomobject]@{
        state = $state
        tracked_count = $tracked.Count
        active_count = $active.Count
        ready_count = $readyCount
        missing_tracked = $missingTracked
        missing_active = $missingActive
        unexpected_tracked = $unexpected
        secrets_exposed = $false
    }
}

function Get-CommandPathSafe {
    param([Parameter(Mandatory = $true)][string]$Name)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) { return $null }
    return $command.Source
}

function Test-TcpEndpoint {
    param(
        [string]$HostName = "127.0.0.1",
        [int]$Port,
        [int]$TimeoutMilliseconds = 500
    )
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync($HostName, $Port)
        return $task.Wait($TimeoutMilliseconds) -and $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Test-HttpEndpoint {
    param([Parameter(Mandatory = $true)][string]$Url, [int]$TimeoutSeconds = 2)
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        return [pscustomobject]@{ reachable = $true; status_code = [int]$response.StatusCode }
    }
    catch {
        $status = $null
        if ($null -ne $_.Exception.Response) {
            try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = $null }
        }
        return [pscustomobject]@{ reachable = $false; status_code = $status }
    }
}

# The SOC Assistant's conversational model is optional: without it the assistant
# gives its built-in answers. Configured is not running, so report which it is.
function Get-AssistantModelStatus {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$EnvValues)
    $engine = if ($EnvValues.Contains("ASSISTANT_AGENT_ENGINE")) { ([string]$EnvValues["ASSISTANT_AGENT_ENGINE"]).Trim().ToLowerInvariant() } else { "" }
    if (-not $engine -or $engine -eq "off") {
        return [pscustomobject]@{ engine = "off"; state = "off"; model = "" }
    }
    if ($engine -ne "ollama") {
        return [pscustomobject]@{ engine = $engine; state = "not_checked"; model = "" }
    }
    $model = if ($EnvValues.Contains("ASSISTANT_AGENT_MODEL") -and [string]$EnvValues["ASSISTANT_AGENT_MODEL"]) { [string]$EnvValues["ASSISTANT_AGENT_MODEL"] } else { "qwen3:8b" }
    $baseUrl = if ($EnvValues.Contains("ASSISTANT_AGENT_BASE_URL") -and [string]$EnvValues["ASSISTANT_AGENT_BASE_URL"]) { ([string]$EnvValues["ASSISTANT_AGENT_BASE_URL"]).TrimEnd("/") } else { "http://127.0.0.1:11434" }
    try {
        $tags = Invoke-RestMethod -Uri "$baseUrl/api/tags" -TimeoutSec 3 -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{ engine = "ollama"; state = "not_running"; model = $model }
    }
    $names = @($tags.models | ForEach-Object { [string]$_.name })
    $state = if ($names -contains $model -or $names -contains "${model}:latest") { "ready" } else { "model_missing" }
    return [pscustomobject]@{ engine = "ollama"; state = $state; model = $model }
}

function Get-AssistantModelSummary {
    param([Parameter(Mandatory = $true)]$Status)
    switch ($Status.state) {
        "ready" { return "ready ($($Status.model))" }
        "not_running" { return "Ollama not running; the SOC Assistant gives built-in answers only. Start the Ollama app." }
        "model_missing" { return "Ollama is running but $($Status.model) is not downloaded; run: ollama pull $($Status.model)" }
        "not_checked" { return "$($Status.engine) (hosted, not checked)" }
        default { return "off (built-in answers)" }
    }
}

function Test-AtdrHasDesktop {
    # Whether this process runs in somebody's sign-in session. A task that runs whether or not anyone is signed in
    # (and every service) is in session 0, which has no desktop: nothing started there can show a window, a tray
    # icon or a notification.
    try {
        return ((Get-Process -Id $PID).SessionId -ne 0)
    }
    catch {
        return $true
    }
}

# Starts the installed Ollama app when the configured model is not running, and
# waits briefly for it. Never fails the launcher: the assistant has a fallback.
function Start-AssistantModelIfStopped {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$EnvValues)
    $status = Get-AssistantModelStatus $EnvValues
    if ($status.state -ne "not_running") { return $status }
    # Ollama's app lives in the notification area of whoever is signed in. Without a desktop it is left to the
    # helper that has one (scripts\desktop_agent.ps1); until someone signs in the assistant gives its built-in answers.
    if (-not (Test-AtdrHasDesktop)) { return $status }
    $app = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama app.exe"
    if (-not (Test-Path -LiteralPath $app -PathType Leaf)) { return $status }
    try {
        Start-Process -FilePath $app -WindowStyle Hidden -ErrorAction Stop | Out-Null
    }
    catch {
        return $status
    }
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        Start-Sleep -Seconds 1
        $status = Get-AssistantModelStatus $EnvValues
        if ($status.state -ne "not_running") { break }
    }
    return $status
}

function Get-SafeDatabaseDialect {
    param([AllowNull()][string]$DatabaseUrl)
    if ([string]::IsNullOrWhiteSpace($DatabaseUrl)) { return "not_configured" }
    if ($DatabaseUrl.StartsWith("sqlite", [System.StringComparison]::OrdinalIgnoreCase)) { return "sqlite" }
    if ($DatabaseUrl.StartsWith("postgresql", [System.StringComparison]::OrdinalIgnoreCase)) { return "postgresql" }
    return "other"
}

function New-PrivateSecret {
    param([int]$Bytes = 48)
    $buffer = New-Object byte[] $Bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
    return [Convert]::ToBase64String($buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Set-DotEnvValues {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Values
    )
    $lines = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $Path) {
        foreach ($existingLine in Get-Content -LiteralPath $Path) {
            [void]$lines.Add([string]$existingLine)
        }
    }
    $seen = @{}
    for ($index = 0; $index -lt $lines.Count; $index += 1) {
        $line = $lines[$index]
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=') {
            $name = $matches[1]
            if ($Values.ContainsKey($name)) {
                $escaped = ([string]$Values[$name]).Replace('"', '\"')
                $lines[$index] = "$name=`"$escaped`""
                $seen[$name] = $true
            }
        }
    }
    foreach ($name in $Values.Keys) {
        if (-not $seen.ContainsKey($name)) {
            $escaped = ([string]$Values[$name]).Replace('"', '\"')
            $lines.Add("$name=`"$escaped`"")
        }
    }
    Set-Content -LiteralPath $Path -Value $lines -Encoding UTF8
}

function Get-MissingShellAuthFields {
    param([hashtable]$EnvironmentValues)
    $required = @(
        "ATDR_AUTH_MODE",
        "MFU_IAM_ENABLED",
        "MFU_IAM_TEMPLATE_SHELL_ENABLED",
        "MFU_IAM_TEMPLATE_SHELL_BASE_URL",
        "MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL",
        "MFU_IAM_ALLOWED_DOMAINS",
        "MFU_IAM_HANDOFF_ENABLED",
        "MFU_IAM_HANDOFF_SHARED_SECRET",
        "MFU_IAM_HANDOFF_ALLOWED_ORIGINS",
        "MFU_SHELL_LOCAL_KEY"
    )
    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $required) {
        if (-not $EnvironmentValues.Contains($name) -or (Test-PlaceholderValue ([string]$EnvironmentValues[$name]))) {
            $missing.Add($name)
        }
    }
    foreach ($name in @("MFU_IAM_ENABLED", "MFU_IAM_TEMPLATE_SHELL_ENABLED", "MFU_IAM_HANDOFF_ENABLED")) {
        if ($EnvironmentValues.Contains($name) -and ([string]$EnvironmentValues[$name]).ToLowerInvariant() -ne "true") {
            $missing.Add("$name=true")
        }
    }
    if ($EnvironmentValues.Contains("ATDR_AUTH_MODE") -and [string]$EnvironmentValues["ATDR_AUTH_MODE"] -ne "template_shell") {
        $missing.Add("ATDR_AUTH_MODE=template_shell")
    }
    return @($missing)
}

function Get-MissingTemplateProviderFields {
    param([hashtable]$EnvironmentValues)

    # These are names only. Values stay inside the supervisor shell's private
    # environment and are never copied into ATDR configuration or output.
    $required = @(
        "MONGODB",
        "IAM_SDK_BASE_URL",
        "IAM_SDK_CLIENT_ID",
        "IAM_SDK_CLIENT_SECRET",
        "IAM_SDK_AUDIENCE",
        "IAM_ADMIN_CLIENT_ID",
        "IAM_ADMIN_CLIENT_SECRET",
        "IAM_ADMIN_AUDIENCE",
        "PROJECT_PERMISSION_TYPE_TITLE",
        "PROJECT_PERMISSION_GROUP_TITLE",
        "PROJECT_AUTH_REQUIRE_2FA"
    )
    return @($required | Where-Object {
        -not $EnvironmentValues.Contains($_) -or
        (Test-PlaceholderValue ([string]$EnvironmentValues[$_])
        )
    })
}

function Get-TemplateGoogleClientStatus {
    param([Parameter(Mandatory = $true)][string]$TemplateRoot)

    $frontendEnvPath = Join-Path $TemplateRoot "frontend-vue\.env.localdev"
    $backendEnvPath = Join-Path $TemplateRoot "backend-node\.env.local"
    $frontendSourcePath = Join-Path $TemplateRoot "frontend-vue\src\main.js"
    $backendSourcePath = Join-Path $TemplateRoot "backend-node\server\Project\accounts\service\account.js"
    $frontendValues = Read-DotEnvFile $frontendEnvPath
    $backendValues = Read-DotEnvFile $backendEnvPath
    $frontendValue = if ($frontendValues.Contains("VUE_APP_CLIENTID")) { [string]$frontendValues["VUE_APP_CLIENTID"] } else { "" }
    $backendValue = if ($backendValues.Contains("GOOGLE_CLIENT_ID")) { [string]$backendValues["GOOGLE_CLIENT_ID"] } else { "" }
    $frontendConfigured = -not (Test-PlaceholderValue $frontendValue)
    $backendConfigured = -not (Test-PlaceholderValue $backendValue)
    $idsMatch = $frontendConfigured -and $backendConfigured -and ($frontendValue -ceq $backendValue)
    $legacyPattern = '(?i)(VUE_APP_CLIENTID|GOOGLE_CLIENT_ID)\s*\|\|[\s\S]{0,180}?[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com'
    $frontendLegacy = $false
    $backendLegacy = $false
    if (Test-Path -LiteralPath $frontendSourcePath -PathType Leaf) {
        $frontendLegacy = [bool](Select-String -LiteralPath $frontendSourcePath -Pattern $legacyPattern -Quiet)
    }
    if (Test-Path -LiteralPath $backendSourcePath -PathType Leaf) {
        $backendLegacy = [bool](Select-String -LiteralPath $backendSourcePath -Pattern $legacyPattern -Quiet)
    }

    $diagnosis = if (-not (Test-Path -LiteralPath $TemplateRoot -PathType Container)) {
        "template_root_missing"
    }
    elseif (-not $frontendConfigured) {
        "frontend_client_not_configured"
    }
    elseif (-not $backendConfigured) {
        "backend_client_not_configured"
    }
    elseif (-not $idsMatch) {
        "client_id_mismatch"
    }
    elseif ($frontendLegacy -or $backendLegacy) {
        "legacy_fallback_present"
    }
    else {
        "ready"
    }

    return [pscustomobject]@{
        ready = ($diagnosis -eq "ready")
        credentials_ready = ($frontendConfigured -and $backendConfigured -and $idsMatch)
        diagnosis = $diagnosis
        frontend_env_exists = (Test-Path -LiteralPath $frontendEnvPath -PathType Leaf)
        backend_env_exists = (Test-Path -LiteralPath $backendEnvPath -PathType Leaf)
        frontend_client_configured = $frontendConfigured
        backend_client_configured = $backendConfigured
        client_ids_match = $idsMatch
        frontend_legacy_fallback_present = $frontendLegacy
        backend_legacy_fallback_present = $backendLegacy
        approved_local_origin = "http://localhost:8080"
        secrets_exposed = $false
    }
}

function Get-TemplateGoogleClientAction {
    param([Parameter(Mandatory = $true)]$Status)

    switch ([string]$Status.diagnosis) {
        "template_root_missing" { return "Select the approved MFU supervisor shell directory." }
        "frontend_client_not_configured" { return "Set VUE_APP_CLIENTID in frontend-vue/.env.localdev using the approved Google OAuth Web client." }
        "backend_client_not_configured" { return "Set GOOGLE_CLIENT_ID in backend-node/.env.local to the same approved Google OAuth Web client." }
        "client_id_mismatch" { return "Make VUE_APP_CLIENTID and GOOGLE_CLIENT_ID identical. Do not paste either value into source control." }
        "legacy_fallback_present" { return "Run .\scripts\setup_team.cmd again so the legacy source fallback can be removed safely." }
        default { return "No Google client configuration action is required." }
    }
}

function Invoke-CheckedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [string]$FailureMessage = "Command failed."
    )
    Push-Location $WorkingDirectory
    try {
        & $FilePath @ArgumentList
        if ($LASTEXITCODE -ne 0) {
            throw $FailureMessage
        }
    }
    finally {
        Pop-Location
    }
}

# ---- Keeping ATDR running (scripts\watch_system.ps1) ----
#
# start_system records that ATDR is meant to run and stop_system that it is meant to be stopped. The watcher
# reads that, so it restarts a part that died but never one that was stopped on purpose.

function Get-AtdrDesiredStatePath {
    return Join-Path (Get-AtdrRuntimeDirectory) "desired-state.json"
}

function Get-AtdrWatchStatusPath {
    return Join-Path (Get-AtdrRuntimeDirectory) "watch-status.json"
}

function ConvertTo-AtdrUtc {
    # A time read back from JSON: Windows PowerShell gives the text, PowerShell 7 a date.
    param($Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try {
        return [datetime]::Parse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    }
    catch {
        return $null
    }
}

function Read-AtdrDesiredState {
    $unknown = [pscustomobject]@{ state = "unknown"; since = $null; by = $null; hold_until = $null }
    $path = Get-AtdrDesiredStatePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $unknown }
    try {
        $value = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    }
    catch {
        return $unknown
    }
    if ($null -eq $value -or [string]$value.state -notin @("running", "stopped")) { return $unknown }
    return [pscustomobject]@{
        state = [string]$value.state
        since = ConvertTo-AtdrUtc $value.since
        by = [string]$value.by
        hold_until = ConvertTo-AtdrUtc $value.hold_until
    }
}

function Set-AtdrDesiredState {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("running", "stopped")][string]$State,
        [Parameter(Mandatory = $true)][string]$By,
        # With a stop only: ATDR stays stopped until then even across a sign-in, and is started again after it.
        [Nullable[datetime]]$HoldUntil = $null
    )
    $runtime = Get-AtdrRuntimeDirectory
    New-Item -ItemType Directory -Path $runtime -Force | Out-Null
    $hold = if ($State -eq "stopped" -and $null -ne $HoldUntil) { ([datetime]$HoldUntil).ToUniversalTime().ToString("o") } else { $null }
    [ordered]@{
        state = $State
        since = (Get-Date).ToUniversalTime().ToString("o")
        by = $By
        hold_until = $hold
    } | ConvertTo-Json | Set-Content -LiteralPath (Get-AtdrDesiredStatePath) -Encoding UTF8
}

function Test-AtdrHeld {
    # A stop that is to outlast a sign-in (stop_system -HoldHours), while its time has not passed.
    param([Parameter(Mandatory = $true)]$Desired, [datetime]$Now = (Get-Date).ToUniversalTime())
    return ($Desired.state -eq "stopped" -and $null -ne $Desired.hold_until -and $Now -lt $Desired.hold_until)
}

function Get-AtdrExpectedParts {
    # The four parts ATDR cannot do without, then the ones .env switches on.
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$EnvValues)
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @("atdr-backend", "atdr-frontend", "shell-backend", "shell-frontend")) { $parts.Add($name) }
    foreach ($pair in @(@("OPERATION_WORKER_ENABLED", "atdr-worker"), @("SYSLOG_ENABLED", "atdr-syslog"))) {
        if ($EnvValues.Contains($pair[0]) -and ([string]$EnvValues[$pair[0]]).ToLowerInvariant() -eq "true") { $parts.Add($pair[1]) }
    }
    return @($parts)
}

function Get-AtdrPartAddress {
    # Where a part answers when it is working. The worker and the syslog receiver have no address.
    param([Parameter(Mandatory = $true)][string]$Name)
    switch ($Name) {
        "atdr-backend" { return "http://127.0.0.1:8000/health/live" }
        "atdr-frontend" { return "http://127.0.0.1:5173" }
        "shell-backend" { return "http://127.0.0.1:8214/healthz" }
        "shell-frontend" { return "http://localhost:8080" }
        default { return $null }
    }
}

function Test-AtdrRestartAllowed {
    # A part that keeps dying is restarted three times in ten minutes, then once every five.
    param(
        [datetime[]]$Restarts = @(),
        [Parameter(Mandatory = $true)][datetime]$Now,
        [int]$QuickRestarts = 3,
        [int]$QuickWindowMinutes = 10,
        [int]$SlowRetryMinutes = 5
    )
    # No restarts yet arrives here as nothing at all, which the pipeline would hand on as one empty item.
    $recent = @(@($Restarts) | Where-Object { $null -ne $_ -and ($Now - $_).TotalMinutes -lt $QuickWindowMinutes })
    if ($recent.Count -lt $QuickRestarts) { return $true }
    $last = ($recent | Sort-Object | Select-Object -Last 1)
    return (($Now - $last).TotalMinutes -ge $SlowRetryMinutes)
}

function Get-AtdrWatchDecision {
    # What the watcher should do now. It decides only; watch_system.ps1 acts.
    param(
        [Parameter(Mandatory = $true)][string]$DesiredState,
        [Nullable[datetime]]$HoldUntil = $null,
        [Parameter(Mandatory = $true)][datetime]$Now,
        [string[]]$Expected = @(),
        [string[]]$Alive = @(),
        # Per part: how many checks in a row its address has not answered, when it was started, when the watcher restarted it.
        [hashtable]$Unanswered = @{},
        [hashtable]$StartedAt = @{},
        [hashtable]$Restarts = @{},
        [int]$UnansweredLimit = 6,
        [int]$GraceSeconds = 300
    )
    $decision = [ordered]@{ action = "none"; resume = $false; start = @(); restart = @(); waiting = @(); reason = "" }
    if ($DesiredState -eq "stopped") {
        if ($null -ne $HoldUntil -and $Now -ge ([datetime]$HoldUntil)) {
            $decision.resume = $true
        }
        else {
            $decision.reason = if ($null -ne $HoldUntil) { "stopped on purpose until $(([datetime]$HoldUntil).ToString('o'))" } else { "stopped on purpose" }
            return [pscustomobject]$decision
        }
    }
    elseif ($DesiredState -ne "running") {
        $decision.reason = "ATDR has not been started with scripts\start_system.cmd yet"
        return [pscustomobject]$decision
    }

    $expectedAlive = @($Expected | Where-Object { $_ -in $Alive })
    if ($expectedAlive.Count -eq 0) {
        $history = if ($Restarts.ContainsKey("*")) { @($Restarts["*"]) } else { @() }
        if (Test-AtdrRestartAllowed -Restarts $history -Now $Now) {
            $decision.action = "start_all"
            $decision.reason = if ($decision.resume) { "the time it was to stay stopped has passed" } else { "no part is running" }
        }
        else {
            $decision.waiting = @("*")
            $decision.reason = "ATDR did not start; trying again every few minutes"
        }
        return [pscustomobject]$decision
    }

    $start = [System.Collections.Generic.List[string]]::new()
    $restart = [System.Collections.Generic.List[string]]::new()
    $waiting = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $Expected) {
        $history = if ($Restarts.ContainsKey($name)) { @($Restarts[$name]) } else { @() }
        $allowed = Test-AtdrRestartAllowed -Restarts $history -Now $Now
        if ($name -notin $Alive) {
            if ($allowed) { $start.Add($name) } else { $waiting.Add($name) }
            continue
        }
        $missed = if ($Unanswered.ContainsKey($name)) { [int]$Unanswered[$name] } else { 0 }
        if ($missed -lt $UnansweredLimit) { continue }
        # A part that has just started may still be loading (the MFU shell compiles for minutes).
        $since = if ($StartedAt.ContainsKey($name) -and $null -ne $StartedAt[$name]) { ($Now - ([datetime]$StartedAt[$name])).TotalSeconds } else { [double]::MaxValue }
        if ($since -lt $GraceSeconds) { continue }
        if ($allowed) { $restart.Add($name) } else { $waiting.Add($name) }
    }
    $decision.start = @($start)
    $decision.restart = @($restart)
    $decision.waiting = @($waiting)
    if ($start.Count -or $restart.Count) {
        $decision.action = "parts"
        $decision.reason = (@(
            $(if ($start.Count) { "stopped: $($start -join ', ')" }),
            $(if ($restart.Count) { "not answering: $($restart -join ', ')" })
        ) | Where-Object { $_ }) -join "; "
    }
    elseif ($waiting.Count) {
        $decision.reason = "keeps stopping: $($waiting -join ', '); trying again every few minutes"
    }
    return [pscustomobject]$decision
}

function Get-AtdrProblemReports {
    # Which problems the watcher should tell people about now, and which it should tell them are over. It decides
    # only; watch_system.ps1 reports through atdr.scripts.notify. A key is a part's name, or "*" for ATDR as a
    # whole (it could not be started).
    param(
        # What has been told and not yet told over.
        [string[]]$Told = @(),
        # What Get-AtdrWatchDecision is waiting on: started three times in ten minutes and down again.
        [string[]]$Waiting = @(),
        [switch]$MeantToRun,
        [string[]]$Expected = @(),
        [string[]]$Alive = @(),
        [hashtable]$StartedAt = @{},
        [Parameter(Mandatory = $true)][datetime]$Now,
        # A part that is tried every five minutes runs for a moment each time: it is over once it has stayed up.
        [int]$SteadySeconds = 600
    )
    $report = @($Waiting | Where-Object { $_ -notin $Told })
    $over = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $Told) {
        if ($key -in $Waiting) { continue }
        # Stopped on purpose: nothing about its parts is a problem any more.
        if (-not $MeantToRun) { $over.Add($key); continue }
        if ($key -eq "*") {
            if ($Expected.Count -and @($Expected | Where-Object { $_ -notin $Alive }).Count -eq 0) { $over.Add($key) }
            continue
        }
        # A part ATDR no longer runs, such as the live syslog receiver after it was switched off.
        if ($key -notin $Expected) { $over.Add($key); continue }
        if ($key -notin $Alive -or -not $StartedAt.ContainsKey($key) -or $null -eq $StartedAt[$key]) { continue }
        if (($Now - ([datetime]$StartedAt[$key])).TotalSeconds -ge $SteadySeconds) { $over.Add($key) }
    }
    return [pscustomobject]@{ report = @($report); over = @($over) }
}

function Enter-AtdrStartLock {
    # One start at a time: the sign-in start and the watcher must not both launch the same parts.
    $runtime = Get-AtdrRuntimeDirectory
    New-Item -ItemType Directory -Path $runtime -Force | Out-Null
    $path = Join-Path $runtime "start.lock"
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        try {
            $held = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            if (Test-TrackedProcessRecordActive $held) { return $false }
        }
        catch { }
    }
    $me = Get-Process -Id $PID
    [ordered]@{ pid = $PID; started_at = $me.StartTime.ToUniversalTime().ToString("o") } |
        ConvertTo-Json | Set-Content -LiteralPath $path -Encoding UTF8
    return $true
}

function Exit-AtdrStartLock {
    $path = Join-Path (Get-AtdrRuntimeDirectory) "start.lock"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
    try {
        $held = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ([int]$held.pid -ne $PID) { return }
    }
    catch { }
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}

function Test-AtdrStartLockHeld {
    $path = Join-Path (Get-AtdrRuntimeDirectory) "start.lock"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
    try {
        return [bool](Test-TrackedProcessRecordActive (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json))
    }
    catch {
        return $false
    }
}

$AtdrWatcherTaskName = "ATDR keep running"

function Start-AtdrWatcherTask {
    # Starts the watcher that scripts\autostart.cmd installed, when it is not running. Nothing happens where it is
    # not installed: ATDR then runs as before, and a part that stops stays stopped.
    try {
        $task = Get-ScheduledTask -TaskName $AtdrWatcherTaskName -ErrorAction Stop
        if ([string]$task.State -ne "Running") { Start-ScheduledTask -TaskName $AtdrWatcherTaskName -ErrorAction Stop }
        return $true
    }
    catch {
        return $false
    }
}

function Test-AtdrWatcherAlive {
    # Whether this folder's watcher runs: by the record it keeps of itself, not by the machine's task, which may
    # belong to another folder.
    $path = Join-Path (Get-AtdrRuntimeDirectory) "watch.lock"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
    try {
        return [bool](Test-TrackedProcessRecordActive (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json))
    }
    catch {
        return $false
    }
}

function Get-AtdrWatcherSession {
    # The Windows session this folder's watcher runs in: 0 is the one without a desktop, which a task that runs
    # without a sign-in is given. Nothing when no watcher runs.
    $path = Join-Path (Get-AtdrRuntimeDirectory) "watch.lock"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $held = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if (-not (Test-TrackedProcessRecordActive $held)) { return $null }
        return [int](Get-Process -Id ([int]$held.pid) -ErrorAction Stop).SessionId
    }
    catch {
        return $null
    }
}

function Stop-AtdrWatcherProcess {
    # Ends the watcher by its own process. Never by ending its task: Windows ends a task together with everything
    # the task started, and a watcher that has brought a part of ATDR back is that part's parent.
    $path = Join-Path (Get-AtdrRuntimeDirectory) "watch.lock"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
    try {
        $held = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if (-not (Test-TrackedProcessRecordActive $held)) { return $false }
        Stop-Process -Id ([int]$held.pid) -Force -ErrorAction Stop
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        return $false
    }
}

function Stop-AtdrDesktopHelperProcess {
    # Ends this folder's helper at the desktop (scripts\desktop_agent.ps1) by its own process, like the watcher.
    # Where its task is installed, Windows starts it again within the minute.
    $path = Join-Path (Get-AtdrRuntimeDirectory) "desktop.lock"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
    try {
        $held = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if (-not (Test-TrackedProcessRecordActive $held)) { return $false }
        Stop-Process -Id ([int]$held.pid) -Force -ErrorAction Stop
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        return $false
    }
}

function Read-AtdrWatchStatus {
    # What the watcher last wrote, with how long ago: it writes at every check, so an old status means no watcher.
    $path = Get-AtdrWatchStatusPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $status = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $checked = ConvertTo-AtdrUtc $status.watcher.checked_at
        $age = if ($null -ne $checked) { ((Get-Date).ToUniversalTime() - $checked).TotalSeconds } else { $null }
        return [pscustomobject]@{ status = $status; age_seconds = $age }
    }
    catch {
        return $null
    }
}

function Restart-AtdrWatcher {
    # Ends the watcher and has its task start it again, so that the watcher which runs is the script now in this
    # folder (a release has just changed the files). False where the task is not installed.
    [void](Stop-AtdrWatcherProcess)
    # The helper at the desktop holds the scripts of the version before too. Ended here, it is started again by
    # its own task within the minute; a notification that comes in between waits for it.
    [void](Stop-AtdrDesktopHelperProcess)
    # Windows needs a moment to see that the watcher which was just ended is gone.
    for ($waited = 0; $waited -lt 20; $waited++) {
        $task = Get-ScheduledTask -TaskName $AtdrWatcherTaskName -ErrorAction SilentlyContinue
        if ($null -eq $task) { return $false }
        if ([string]$task.State -ne "Running") { break }
        Start-Sleep -Milliseconds 500
    }
    if (Start-AtdrWatcherTask) { return $true }
    # The task is there and this window may not start it (one that runs without a sign-in was registered by an
    # administrator). Windows starts it by itself within the minute.
    for ($waited = 0; $waited -lt 45; $waited++) {
        if (Test-AtdrWatcherAlive) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

# ---- Releases (scripts\release.cmd) ----
#
# ATDR runs from a copy of its own, which only ever holds a version that was committed and checked. The folder it is
# developed in records where that copy is; the copy records which version it holds.

function Get-AtdrLiveCopy {
    # Where ATDR runs from, when this folder is the one it is developed in. Nothing in the live copy itself, and
    # nothing on a machine where ATDR still runs from the folder it is developed in.
    $path = Join-Path (Get-AtdrRuntimeDirectory) "live-copy.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $root = [string](Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).root
        if ([string]::IsNullOrWhiteSpace($root)) { return $null }
        return $root
    }
    catch {
        return $null
    }
}

function Get-AtdrReleasedVersion {
    # Which released version a live copy holds (the release writes it); nothing in a folder that is not one.
    $path = Join-Path (Get-AtdrRuntimeDirectory) "release.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ([string]::IsNullOrWhiteSpace([string]$record.short)) { return $null }
        return [pscustomobject]@{ short = [string]$record.short; released_at = ConvertTo-AtdrUtc $record.released_at; check = [string]$record.check }
    }
    catch {
        return $null
    }
}

function Get-AtdrUnfinishedRelease {
    # A release that was cut off (the machine went down in the middle of it): this folder may hold half of one
    # version and half of another. The release writes this before it changes a file and removes it at the end.
    $path = Join-Path (Get-AtdrRuntimeDirectory) "release-in-progress.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $value = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        # The release names the process that makes it. While that process runs the release is under way, and it
        # starts ATDR itself; once it is gone, the release was cut off.
        $driver = if ($value.PSObject.Properties["driver"]) { $value.driver } else { $null }
        $source = if ($value.PSObject.Properties["source"]) { [string]$value.source } else { "" }
        return [pscustomobject]@{
            started_at = ConvertTo-AtdrUtc $value.started_at
            source = $source
            under_way = [bool]($null -ne $driver -and (Test-TrackedProcessRecordActive $driver))
        }
    }
    catch {
        # Unreadable is still unfinished.
        return [pscustomobject]@{ started_at = $null; source = ""; under_way = $false }
    }
}

function Get-AtdrStartRequestPath {
    # A release has stopped ATDR's own parts and asks the watcher to start them: started by the watcher they belong
    # to its task, like any part it brings back; started by the release they would end with the release's window.
    return Join-Path (Get-AtdrRuntimeDirectory) "start-request.json"
}

function Get-AtdrStartResultPath {
    return Join-Path (Get-AtdrRuntimeDirectory) "start-result.json"
}

function Request-AtdrStart {
    # Asks the watcher to start whatever of ATDR is not running, and waits for its answer: an object with ok,
    # code and said, or nothing when no watcher answered in time.
    param(
        [Parameter(Mandatory = $true)][string]$By,
        [switch]$Release,
        [int]$TimeoutSeconds = 480
    )
    $id = [guid]::NewGuid().ToString("N")
    $requestPath = Get-AtdrStartRequestPath
    $resultPath = Get-AtdrStartResultPath
    New-Item -ItemType Directory -Path (Get-AtdrRuntimeDirectory) -Force | Out-Null
    Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
    # Written whole, then moved into place: the watcher never reads half a request.
    [ordered]@{ id = $id; by = $By; release = [bool]$Release; at = (Get-Date).ToUniversalTime().ToString("o") } |
        ConvertTo-Json | Set-Content -LiteralPath "$requestPath.arriving" -Encoding UTF8
    Move-Item -LiteralPath "$requestPath.arriving" -Destination $requestPath -Force
    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
            try {
                $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
                if ([string]$result.id -eq $id) {
                    Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
                    return $result
                }
            }
            catch { }
        }
        Start-Sleep -Milliseconds 500
    }
    Remove-Item -LiteralPath $requestPath -Force -ErrorAction SilentlyContinue
    return $null
}

# ---- Running without a sign-in (scripts\autostart.cmd -BeforeSignIn) ----
#
# Installed for a sign-in, ATDR's watcher and every part it starts belong to that sign-in session: nothing runs before
# someone signs in, and everything ends when they sign out. Installed to run before sign-in, the watcher is a task
# Windows starts with the machine, with no desktop, and every start of ATDR goes through it.

$AtdrSignInTaskName = "ATDR start at sign-in"
$AtdrDesktopTaskName = "ATDR at the desktop"

function Get-AtdrAutostartRecordPath {
    return Join-Path (Get-AtdrRuntimeDirectory) "autostart.json"
}

function Read-AtdrAutostartRecord {
    # How scripts\autostart.cmd last installed this folder's tasks; nothing where it never did.
    $path = Get-AtdrAutostartRecordPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ([string]$record.mode -notin @("before_sign_in", "at_sign_in")) { return $null }
        return $record
    }
    catch {
        return $null
    }
}

function Test-AtdrRunsWithoutSignIn {
    # By this folder's own record, not by what tasks the machine has: a copy of these scripts in another folder
    # (a test's, a second checkout) is not the one the machine's tasks belong to.
    $record = Read-AtdrAutostartRecord
    return ($null -ne $record -and [string]$record.mode -eq "before_sign_in")
}

function Get-AtdrDesktopQueuePath {
    # Where a part of ATDR that has no desktop leaves a Windows notification for the helper that has one.
    return Join-Path (Get-AtdrRuntimeDirectory) "desktop-notifications"
}

function ConvertFrom-AtdrPowerQuery {
    # The seconds on mains power in what `powercfg /query <plan> SUB_SLEEP STANDBYIDLE` prints; nothing when it does
    # not say. 0 means the machine never goes to sleep by itself.
    param([AllowNull()][string[]]$Lines)
    foreach ($line in @($Lines)) {
        if ([string]$line -match 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)') { return [Convert]::ToInt32($matches[1], 16) }
    }
    return $null
}

function Get-AtdrPowerPlans {
    # The identifier of every power plan the machine has. A laptop's own performance modes switch between several.
    $plans = [System.Collections.Generic.List[string]]::new()
    foreach ($line in @(powercfg /list 2>$null)) {
        if ([string]$line -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') { $plans.Add($matches[1].ToLowerInvariant()) }
    }
    return @($plans)
}

function Get-AtdrMainsSleepSeconds {
    # After how long without use the machine goes to sleep on mains power: by the plan in use, or by the one named.
    param([string]$Plan = "SCHEME_CURRENT")
    return (ConvertFrom-AtdrPowerQuery @(powercfg /query $Plan SUB_SLEEP STANDBYIDLE 2>$null))
}
