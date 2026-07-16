[CmdletBinding()]
param(
    [string]$TemplateRoot,
    [switch]$Json,
    [switch]$RequireReady
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

try {
    $root = Get-AtdrProjectRoot
    $resolvedTemplate = $null
    $templateError = $null
    try { $resolvedTemplate = Resolve-TemplateRoot $TemplateRoot } catch { $templateError = $_.Exception.Message }

    $structure = if ($resolvedTemplate) { Test-TemplateShellStructure $resolvedTemplate } else { [pscustomobject]@{ valid = $false; missing = @("MFU_TEMPLATE_ROOT") } }
    $envPath = Join-Path $root ".env"
    $envValues = Read-DotEnvFile $envPath
    $missingAuth = @(Get-MissingShellAuthFields $envValues)
    $pythonPath = Join-Path $root ".venv\Scripts\python.exe"
    $nodePath = Get-CommandPathSafe "node"
    $npmPath = Get-CommandPathSafe "npm.cmd"
    if (-not $npmPath) { $npmPath = Get-CommandPathSafe "npm" }
    $nodeVersion = $null
    if ($nodePath) { $nodeVersion = (& $nodePath --version 2>$null) }
    $nodeVersionOk = Test-NodeVersionSupported $nodeVersion
    $pythonPipReady = Test-PythonPip $pythonPath

    $shellBackendEnv = if ($resolvedTemplate) { Join-Path $resolvedTemplate "backend-node\.env.local" } else { "" }
    $shellEnvValues = if ($shellBackendEnv) { Read-DotEnvFile $shellBackendEnv } else { [ordered]@{} }
    $missingShellPrivate = @(Get-MissingTemplateProviderFields $shellEnvValues)
    $iamProxyConfigured = $missingShellPrivate.Count -eq 0
    $googleStatus = if ($resolvedTemplate) { Get-TemplateGoogleClientStatus $resolvedTemplate } else { [pscustomobject]@{
        ready = $false; credentials_ready = $false; diagnosis = "template_root_missing";
        frontend_client_configured = $false; backend_client_configured = $false; client_ids_match = $false;
        frontend_legacy_fallback_present = $false; backend_legacy_fallback_present = $false;
        approved_local_origin = "http://localhost:8080"; secrets_exposed = $false
    } }

    $mongoReady = Test-TcpEndpoint -Port 27017
    $services = [ordered]@{
        atdr_backend = Test-HttpEndpoint "http://127.0.0.1:8000/health/live"
        atdr_frontend = Test-HttpEndpoint "http://127.0.0.1:5173"
        shell_backend = Test-HttpEndpoint "http://127.0.0.1:8214/healthz"
        # The legacy Vue/Webpack shell may briefly respond slowly after a cold
        # compile even though its listener is already healthy.
        shell_frontend = Test-HttpEndpoint -Url "http://localhost:8080" -TimeoutSeconds 10
    }
    $allServicesReady = @($services.Values | Where-Object { -not $_.reachable }).Count -eq 0

    $authMode = if ($envValues.Contains("ATDR_AUTH_MODE")) { [string]$envValues["ATDR_AUTH_MODE"] } else { "not_configured" }
    $databaseDialect = Get-SafeDatabaseDialect $(if ($envValues.Contains("DATABASE_URL")) { [string]$envValues["DATABASE_URL"] } else { "" })
    $responseSimulation = $envValues.Contains("RESPONSE_SIMULATION") -and ([string]$envValues["RESPONSE_SIMULATION"]).ToLowerInvariant() -eq "true"
    $geminiKeyConfigured = $false
    foreach ($keyName in @("ASSISTANT_LLM_API_KEY", "ASSISTANT_API_KEY", "GEMINI_API_KEY")) {
        if ($envValues.Contains($keyName) -and -not (Test-PlaceholderValue ([string]$envValues[$keyName]))) { $geminiKeyConfigured = $true }
    }

    $installationReady = [bool](
        $structure.valid -and
        (Test-Path -LiteralPath $pythonPath -PathType Leaf) -and
        $pythonPipReady -and
        $nodeVersionOk -and
        [bool]$npmPath -and
        (Test-Path -LiteralPath $envPath -PathType Leaf) -and
        $missingAuth.Count -eq 0 -and
        $responseSimulation
    )
    $providerReady = [bool]($missingShellPrivate.Count -eq 0 -and $googleStatus.ready -and $mongoReady)
    $ok = $installationReady
    if ($RequireReady) { $ok = $installationReady -and $providerReady -and $allServicesReady }

    $report = [ordered]@{
        ok = $ok
        project_root = $root
        template_root = $resolvedTemplate
        template_error = $templateError
        template_structure_valid = $structure.valid
        template_missing_files = @($structure.missing)
        installation_ready = $installationReady
        provider_ready = $providerReady
        dependencies = [ordered]@{
            python_venv = (Test-Path -LiteralPath $pythonPath -PathType Leaf)
            python_pip = $pythonPipReady
            node_20_19_or_newer = $nodeVersionOk
            node_version = $nodeVersion
            npm = [bool]$npmPath
            mongodb_reachable = $mongoReady
        }
        configuration = [ordered]@{
            env_exists = (Test-Path -LiteralPath $envPath -PathType Leaf)
            auth_mode = $authMode
            missing_auth_field_names = @($missingAuth)
            missing_shell_private_field_names = @($missingShellPrivate)
            database_dialect = $databaseDialect
            response_simulation = $responseSimulation
            gemini_configured = $geminiKeyConfigured
            secrets_exposed = $false
        }
        identity_provider = [ordered]@{
            iam_proxy_configured = $iamProxyConfigured
            google_auth_ready = $googleStatus.ready
            google_auth_diagnosis = $googleStatus.diagnosis
            google_frontend_client_configured = $googleStatus.frontend_client_configured
            google_backend_client_configured = $googleStatus.backend_client_configured
            google_client_ids_match = $googleStatus.client_ids_match
            legacy_google_client_fallback_present = [bool]($googleStatus.frontend_legacy_fallback_present -or $googleStatus.backend_legacy_fallback_present)
            approved_local_origin = $googleStatus.approved_local_origin
            account_scope_acceptance = "not_validated"
            acceptance_requires_real_sign_in = $true
            secrets_exposed = $false
        }
        services = $services
        all_services_ready = $allServicesReady
        runtime_metadata_exists = (Test-Path -LiteralPath (Join-Path (Get-AtdrRuntimeDirectory) "system-processes.json"))
        secrets_exposed = $false
    }

    if ($Json) {
        $report | ConvertTo-Json -Depth 8
    }
    else {
        Write-Host "ATDR system preflight" -ForegroundColor Cyan
        Write-Host "  Authentication: $authMode"
        Write-Host "  Template shell: $(if ($structure.valid) { 'found' } else { 'missing or invalid' })"
        Write-Host "  MFU IAM proxy: $(if ($iamProxyConfigured) { 'configured' } else { 'incomplete' })"
        Write-Host "  Google authentication: $(if ($googleStatus.ready) { 'ready' } else { "not ready ($($googleStatus.diagnosis))" })"
        Write-Host "  MFU account acceptance: not validated (requires a real sign-in)"
        Write-Host "  Installation readiness: $installationReady"
        Write-Host "  Provider readiness: $providerReady"
        Write-Host "  Python venv/pip: $($report.dependencies.python_venv)/$pythonPipReady"
        Write-Host "  Node 20.19+: $nodeVersionOk $(if ($nodeVersion) { "($nodeVersion)" } else { '' })"
        Write-Host "  MongoDB: $(if ($mongoReady) { 'reachable' } else { 'not reachable on 127.0.0.1:27017' })"
        Write-Host "  Database: $databaseDialect"
        Write-Host "  Response simulation: $responseSimulation"
        Write-Host "  Gemini configured: $geminiKeyConfigured"
        if ($missingAuth.Count) { Write-Host "  Missing ATDR settings: $($missingAuth -join ', ')" -ForegroundColor Yellow }
        if ($missingShellPrivate.Count) { Write-Host "  Missing shell settings: $($missingShellPrivate -join ', ')" -ForegroundColor Yellow }
        if (-not $googleStatus.ready) { Write-Host "  Action: $(Get-TemplateGoogleClientAction $googleStatus)" -ForegroundColor Yellow }
        if (-not $mongoReady) { Write-Host "  Action: start MongoDB for the supervisor shell; ATDR itself does not use MongoDB." -ForegroundColor Yellow }
        Write-Host "  Running services: $(@($services.Values | Where-Object reachable).Count)/4"
        Write-Host "  Preflight: $(if ($ok) { 'PASS' } else { 'NEEDS ATTENTION' })" -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' })
    }
    if (-not $ok) { exit 1 }
}
catch {
    [Console]::Error.WriteLine("ATDR system check failed: $($_.Exception.Message)")
    exit 1
}
