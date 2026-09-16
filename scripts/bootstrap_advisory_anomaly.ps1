[CmdletBinding()]
param(
    [string]$EvidencePath,
    [switch]$UseCommittedSyntheticSample,
    [int]$Limit = 50000,
    [switch]$Execute,
    [string]$Confirm = "",
    [switch]$ReplaceExisting,
    [switch]$Pretty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "ATDR Python environment is unavailable. Run .\scripts\setup_team.cmd first."
}

$arguments = @(
    "-m",
    "atdr.scripts.run_v561_governed_anomaly_bootstrap",
    "--limit",
    [string]$Limit
)
if ($EvidencePath) { $arguments += @("--evidence-path", $EvidencePath) }
if ($UseCommittedSyntheticSample) { $arguments += "--use-committed-synthetic-sample" }
if ($Execute) { $arguments += "--execute" }
if ($Confirm) { $arguments += @("--confirm", $Confirm) }
if ($ReplaceExisting) { $arguments += "--replace-existing" }
if ($Pretty) { $arguments += "--pretty" }

Push-Location $root
try {
    & $python @arguments
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
