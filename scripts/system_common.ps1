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
        throw "Private team configuration is invalid. Run .\scripts\setup_team.ps1 again."
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
    throw "MFU supervisor shell path is not configured. Run .\scripts\setup_team.ps1 -TemplateRoot <path>."
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
        "legacy_fallback_present" { return "Run setup_team again so the legacy source fallback can be removed safely." }
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
