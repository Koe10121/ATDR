[CmdletBinding()]
param(
    [string]$TemplateRoot,
    [string]$ShellPackage,
    [string]$ShellPrivateConfigRoot,
    [switch]$DryRun,
    [switch]$SkipDependencyInstall,
    [switch]$UpdateExistingConfig,
    [switch]$RequireProviderReady
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

function Write-Step([string]$Message) {
    Write-Host "[ATDR setup] $Message" -ForegroundColor Cyan
}

try {
    $root = Get-AtdrProjectRoot
    $usingDirectory = -not [string]::IsNullOrWhiteSpace($TemplateRoot)
    $usingPackage = -not [string]::IsNullOrWhiteSpace($ShellPackage)
    if ($usingDirectory -eq $usingPackage) {
        throw "Choose exactly one shell source: -ShellPackage <approved zip> or -TemplateRoot <approved directory>."
    }
    $pyLauncher = Get-CommandPathSafe "py"
    $systemPython = Get-CommandPathSafe "python"
    $nodePath = Get-CommandPathSafe "node"
    $npmPath = Get-CommandPathSafe "npm.cmd"
    if (-not $npmPath) { $npmPath = Get-CommandPathSafe "npm" }
    if (-not $nodePath) { throw "Node.js is missing. Install Node.js 20.19 or newer, then rerun setup." }
    if (-not $npmPath) { throw "npm is missing. Install Node.js 20.19 or newer with npm, then rerun setup." }
    $nodeVersion = & $nodePath --version
    if (-not (Test-NodeVersionSupported $nodeVersion)) {
        throw "Node.js 20.19 or newer is required by the frontend toolchain. Detected: $nodeVersion"
    }

    $venvPython = Join-Path $root ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $venvPython) -and -not $pyLauncher -and -not $systemPython) {
        throw "Python 3.11 is missing. Install Python 3.11 and enable the py launcher, then rerun setup."
    }

    $runtime = Get-AtdrRuntimeDirectory
    $packageResult = $null
    $shellDistributionMode = "approved_directory"
    if ($usingPackage) {
        $packagePath = [System.IO.Path]::GetFullPath($ShellPackage)
        if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
            throw "The selected MFU shell package does not exist."
        }
        $bootstrapPython = $null
        $bootstrapPrefix = @()
        if ($pyLauncher) {
            $bootstrapPython = $pyLauncher
            $bootstrapPrefix = @("-3.11")
        }
        elseif ($systemPython) {
            $bootstrapPython = $systemPython
        }
        else {
            $bootstrapPython = $venvPython
        }
        $packageArguments = @(
            "-m", "atdr.scripts.mfu_shell_package",
            $(if ($DryRun) { "--verify-package" } else { "--install" }),
            "--package", $packagePath,
            "--contract", (Get-TemplateShellContractPath)
        )
        if (-not $DryRun) {
            New-Item -ItemType Directory -Path $runtime -Force | Out-Null
            $packageArguments += @(
                "--install-base", (Join-Path $runtime "shell"),
                "--confirm", "INSTALL_VERIFIED_MFU_SHELL"
            )
        }
        $allArguments = @($bootstrapPrefix) + $packageArguments
        $packageOutput = @(& $bootstrapPython @allArguments)
        if ($LASTEXITCODE -ne 0) {
            throw "MFU shell package verification or installation failed."
        }
        try { $packageResult = ($packageOutput -join "`n") | ConvertFrom-Json } catch { throw "MFU shell package returned an invalid result." }
        if (-not $packageResult.ok) { throw "MFU shell package verification or installation failed." }
        $shellDistributionMode = "versioned_package"
        if ($DryRun) {
            $template = $null
            $contract = Read-TemplateShellContract
            $structure = [pscustomobject]@{
                valid = $true
                missing = @()
                contract_version = [int]$contract.contract_version
                distribution_mode = [string]$contract.distribution_mode
                source_revision_status = [string]$contract.source_revision_status
            }
        }
        else {
            $template = [System.IO.Path]::GetFullPath([string]$packageResult.install_root)
            if (-not [string]::IsNullOrWhiteSpace($ShellPrivateConfigRoot)) {
                $privateRoot = [System.IO.Path]::GetFullPath($ShellPrivateConfigRoot)
                if (-not (Test-Path -LiteralPath $privateRoot -PathType Container)) {
                    throw "The MFU shell private configuration directory does not exist."
                }
                $privateCopy = Copy-MfuShellPrivateConfiguration -SourceRoot $privateRoot -DestinationRoot $template
                if ($privateCopy.missing.Count) {
                    Write-Host "  Private configuration is incomplete; provider start remains blocked." -ForegroundColor Yellow
                }
            }
            $structure = Test-TemplateShellStructure $template
        }
    }
    else {
        $template = [System.IO.Path]::GetFullPath($TemplateRoot)
        $structure = Test-TemplateShellStructure $template
    }
    if (-not $structure.valid) {
        throw "The selected MFU shell is incomplete. Missing: $($structure.missing -join ', ')"
    }

    $envPath = Join-Path $root ".env"
    $shellExample = Join-Path $root ".env.shell.example"
    if (-not (Test-Path -LiteralPath $shellExample)) { throw ".env.shell.example is missing from the ATDR repository." }
    $envExists = Test-Path -LiteralPath $envPath
    if ($envExists -and -not $UpdateExistingConfig -and -not $DryRun) {
        $current = Read-DotEnvFile $envPath
        $missing = @(Get-MissingShellAuthFields $current)
        if ($missing.Count) {
            throw "Existing .env is preserved and is not shell-ready. Back it up, then rerun with -UpdateExistingConfig. Missing: $($missing -join ', ')"
        }
    }

    $providerRoot = if ($template) { $template } elseif (-not [string]::IsNullOrWhiteSpace($ShellPrivateConfigRoot)) { [System.IO.Path]::GetFullPath($ShellPrivateConfigRoot) } else { $null }
    $shellBackendEnv = if ($providerRoot) { Join-Path $providerRoot "backend-node\.env.local" } else { "" }
    $shellPrivate = if ($shellBackendEnv) { Read-DotEnvFile $shellBackendEnv } else { [ordered]@{} }
    $missingProvider = @(Get-MissingTemplateProviderFields $shellPrivate)
    $googleStatus = if ($providerRoot) { Get-TemplateGoogleClientStatus $providerRoot } else { [pscustomobject]@{
        ready = $false; credentials_ready = $false; diagnosis = "private_config_not_supplied";
        frontend_client_configured = $false; backend_client_configured = $false; client_ids_match = $false;
        frontend_legacy_fallback_present = $false; backend_legacy_fallback_present = $false;
        secrets_exposed = $false
    } }
    $providerReady = ($missingProvider.Count -eq 0) -and $googleStatus.ready
    $providerBlocker = Get-MfuProviderBlocker -MissingProviderFields $missingProvider -GoogleStatus $googleStatus
    if ($RequireProviderReady -and -not $providerReady) {
        throw "MFU identity provider is not ready. $providerBlocker Setup can run without provider acceptance; start remains fail-closed."
    }

    Write-Step "ATDR root: $root"
    Write-Step "MFU shell: $(if ($template) { $template } else { [string]$packageResult.archive_name })"
    Write-Step "Node: $nodeVersion"
    Write-Step "MFU shell contract: v$($structure.contract_version) ($($structure.distribution_mode))"
    Write-Step "Shell distribution: $shellDistributionMode$(if ($packageResult) { " / $($packageResult.release_version)" } else { '' })"
    Write-Step "Mode: $(if ($DryRun) { 'dry run (no changes)' } else { 'apply' })"
    if (-not $providerReady) {
        Write-Host "  Provider acceptance blocker: $providerBlocker" -ForegroundColor Yellow
    }

    if ($DryRun) {
        Write-Step "Would create/install the Python environment and JavaScript dependencies when missing."
        Write-Step "Would create or safely update private shell-mode configuration."
        if ($usingDirectory -and -not $googleStatus.ready) {
            Write-Step "Would remove the legacy Google client fallback without changing private environment values."
        }
        Write-Step "Would back up SQLite before running Alembic migrations."
        Write-Step "Dry run passed. Installation can proceed; provider acceptance is reported separately."
        Write-Step "No file, dependency, or database changes were made."
        exit 0
    }

    New-Item -ItemType Directory -Path $runtime -Force | Out-Null

    if (-not (Test-Path -LiteralPath $venvPython)) {
        Write-Step "Creating Python 3.11 virtual environment."
        if ($pyLauncher) {
            Invoke-CheckedProcess -FilePath $pyLauncher -ArgumentList @("-3.11", "-m", "venv", ".venv") -WorkingDirectory $root -FailureMessage "Python 3.11 virtual environment creation failed."
        }
        else {
            Invoke-CheckedProcess -FilePath $systemPython -ArgumentList @("-m", "venv", ".venv") -WorkingDirectory $root -FailureMessage "Python virtual environment creation failed."
        }
    }

    if (-not (Test-PythonPip $venvPython)) {
        Write-Step "Python virtual environment is missing pip; restoring it with ensurepip."
        try {
            Invoke-CheckedProcess -FilePath $venvPython -ArgumentList @("-m", "ensurepip", "--upgrade") -WorkingDirectory $root -FailureMessage "Python pip recovery failed."
        }
        catch {
            Write-Step "pip recovery did not succeed; preserving the broken environment and creating a clean one."
        }
    }
    if (-not (Test-PythonPip $venvPython)) {
        $brokenRoot = Join-Path $runtime "broken-venvs"
        New-Item -ItemType Directory -Path $brokenRoot -Force | Out-Null
        $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
        $brokenPath = Join-Path $brokenRoot ".venv.$stamp"
        Move-Item -LiteralPath (Join-Path $root ".venv") -Destination $brokenPath
        Write-Step "Preserved broken environment under .atdr_runtime\broken-venvs and recreating Python 3.11 venv."
        if ($pyLauncher) {
            Invoke-CheckedProcess -FilePath $pyLauncher -ArgumentList @("-3.11", "-m", "venv", ".venv") -WorkingDirectory $root -FailureMessage "Python 3.11 virtual environment recreation failed."
        }
        else {
            Invoke-CheckedProcess -FilePath $systemPython -ArgumentList @("-m", "venv", ".venv") -WorkingDirectory $root -FailureMessage "Python virtual environment recreation failed."
        }
        if (-not (Test-PythonPip $venvPython)) {
            throw "The recreated Python environment still has no working pip. Repair the Python 3.11 installation and rerun setup."
        }
    }

    if (-not $SkipDependencyInstall) {
        $requirementsFile = if (Test-Path -LiteralPath (Join-Path $root "requirements.lock.txt")) { "requirements.lock.txt" } else { "requirements.txt" }
        Write-Step "Installing backend dependencies from $requirementsFile."
        Invoke-CheckedProcess -FilePath $venvPython -ArgumentList @("-m", "pip", "install", "-r", $requirementsFile) -WorkingDirectory $root -FailureMessage "Backend dependency installation failed."
        foreach ($directory in @(
            (Join-Path $root "frontend"),
            (Join-Path $template "backend-node"),
            (Join-Path $template "frontend-vue")
        )) {
            if (-not (Test-Path -LiteralPath (Join-Path $directory "node_modules"))) {
                Write-Step "Installing dependencies in $([System.IO.Path]::GetFileName($directory))."
                $npmArgs = if (Test-Path -LiteralPath (Join-Path $directory "package-lock.json")) { @("ci") } else { @("install") }
                Invoke-CheckedProcess -FilePath $npmPath -ArgumentList $npmArgs -WorkingDirectory $directory -FailureMessage "npm dependency installation failed in $directory."
            }
        }
    }

    if ($googleStatus.credentials_ready -and -not $googleStatus.ready) {
        if ($shellDistributionMode -eq "versioned_package") {
            throw "The versioned MFU shell package requires source hardening. Rebuild a sanitized release instead of modifying installed package source."
        }
        Write-Step "Removing the legacy Google client fallback from the approved shell."
        Invoke-CheckedProcess -FilePath $venvPython -ArgumentList @(
            "-m", "atdr.scripts.harden_template_google_auth",
            "--template-root", $template,
            "--runtime-root", $runtime,
            "--apply"
        ) -WorkingDirectory $root -FailureMessage "MFU shell Google authentication hardening failed."
        $googleStatus = Get-TemplateGoogleClientStatus $template
        $providerReady = ($missingProvider.Count -eq 0) -and $googleStatus.ready
    }

    $writeRootEnvironment = (-not $envExists) -or $UpdateExistingConfig
    if (-not $envExists) {
        Copy-Item -LiteralPath $shellExample -Destination $envPath
    }
    elseif ($UpdateExistingConfig) {
        $backupDir = Join-Path $runtime "config-backups"
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
        Copy-Item -LiteralPath $envPath -Destination (Join-Path $backupDir ".env.$stamp.bak")
    }

    if ($writeRootEnvironment) {
        $currentEnv = Read-DotEnvFile $envPath
        $handoffSecret = if ($currentEnv.Contains("MFU_IAM_HANDOFF_SHARED_SECRET") -and -not (Test-PlaceholderValue ([string]$currentEnv["MFU_IAM_HANDOFF_SHARED_SECRET"]))) { [string]$currentEnv["MFU_IAM_HANDOFF_SHARED_SECRET"] } else { New-PrivateSecret }
        $jwtSecret = if ($currentEnv.Contains("JWT_SECRET_KEY") -and -not (Test-PlaceholderValue ([string]$currentEnv["JWT_SECRET_KEY"]))) { [string]$currentEnv["JWT_SECRET_KEY"] } else { New-PrivateSecret }
        $shellLocalKey = if ($currentEnv.Contains("MFU_SHELL_LOCAL_KEY") -and -not (Test-PlaceholderValue ([string]$currentEnv["MFU_SHELL_LOCAL_KEY"]))) { [string]$currentEnv["MFU_SHELL_LOCAL_KEY"] } else { New-PrivateSecret }
        $configValues = @{
            ATDR_AUTH_MODE = "template_shell"
            JWT_SECRET_KEY = $jwtSecret
            MFU_SHELL_LOCAL_KEY = $shellLocalKey
            MFU_IAM_ENABLED = "true"
            MFU_IAM_TEMPLATE_SHELL_ENABLED = "true"
            MFU_IAM_TEMPLATE_SHELL_BASE_URL = "http://127.0.0.1:8214"
            MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL = "http://localhost:8080/#/pages/login"
            MFU_IAM_ALLOWED_DOMAINS = "lamduan.mfu.ac.th"
            MFU_IAM_HANDOFF_ENABLED = "true"
            MFU_IAM_HANDOFF_SHARED_SECRET = $handoffSecret
            MFU_IAM_HANDOFF_ALLOWED_ORIGINS = "http://localhost:8080,http://127.0.0.1:8080"
            MFU_IAM_HANDOFF_FRONTEND_URL = "http://127.0.0.1:5173"
            CORS_ALLOWED_ORIGINS = "http://127.0.0.1:5173,http://localhost:5173"
            RESPONSE_SIMULATION = "true"
            ASSISTANT_ALLOW_RAW_LOG_CONTEXT = "false"
        }
        Set-DotEnvValues -Path $envPath -Values $configValues
    }

    $frontendPrivateEnv = Join-Path $root "frontend\.env.local"
    if (-not (Test-Path -LiteralPath $frontendPrivateEnv)) {
        Set-Content -LiteralPath $frontendPrivateEnv -Value @("VITE_API_BASE_URL=http://127.0.0.1:8000", "VITE_ATDR_PRESENTATION_MODE=false") -Encoding UTF8
    }

    $teamConfig = [ordered]@{
        version = 3
        template_root = $template
        shell_distribution_mode = $shellDistributionMode
        shell_contract_version = $structure.contract_version
        shell_release_version = $(if ($packageResult) { [string]$packageResult.release_version } else { $null })
        shell_archive_sha256 = $(if ($packageResult) { [string]$packageResult.archive_sha256 } else { $null })
        shell_package_verified = [bool]($shellDistributionMode -eq "versioned_package")
        shell_source_fingerprint = $(if ($packageResult) { [string]$packageResult.source_fingerprint } else { Get-TemplateShellFingerprint $template })
        shell_source_revision_status = $structure.source_revision_status
        installation_ready = $true
        provider_configuration_ready = $providerReady
        atdr_backend_url = "http://127.0.0.1:8000"
        atdr_frontend_url = "http://127.0.0.1:5173"
        shell_backend_url = "http://127.0.0.1:8214"
        shell_frontend_url = "http://localhost:8080"
        configured_at = (Get-Date).ToUniversalTime().ToString("o")
        secrets_stored = $false
    }
    $teamConfig | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Get-TeamConfigPath) -Encoding UTF8

    $databaseUrl = (Read-DotEnvFile $envPath)["DATABASE_URL"]
    if ((Get-SafeDatabaseDialect $databaseUrl) -eq "sqlite") {
        $dbPath = Join-Path $root "atdr.db"
        if (Test-Path -LiteralPath $dbPath) {
            $backupDir = Join-Path $root "backups\team-setup"
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
            $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
            Copy-Item -LiteralPath $dbPath -Destination (Join-Path $backupDir "atdr.$stamp.db")
            Write-Step "SQLite backup created before migration."
        }
    }

    Write-Step "Applying Alembic migrations without resetting data."
    Invoke-CheckedProcess -FilePath $venvPython -ArgumentList @("-m", "alembic", "upgrade", "head") -WorkingDirectory $root -FailureMessage "Alembic migration failed. The existing database was not reset."

    $mongoReady = Test-TcpEndpoint -Port 27017
    Write-Step "Installation setup complete."
    Write-Host "  Start: .\scripts\start_system.ps1" -ForegroundColor Green
    if (-not $mongoReady) {
        Write-Host "  Before start: install/start MongoDB on 127.0.0.1:27017 for the MFU shell." -ForegroundColor Yellow
    }
    Write-Host "  IAM/provider credentials remain owned by the private MFU shell configuration; no secret was printed."
    Write-Host "  Provider configuration: $(if ($providerReady) { 'ready for acceptance testing' } else { 'not ready; start will remain fail-closed' })"
    Write-Host "  Provider acceptance is not proven by setup; validate one approved MFU account after startup." -ForegroundColor Yellow
}
catch {
    [Console]::Error.WriteLine("ATDR setup failed: $($_.Exception.Message)")
    exit 1
}
