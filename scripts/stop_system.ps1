[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

try {
    $metadataPath = Join-Path (Get-AtdrRuntimeDirectory) "system-processes.json"
    if (-not (Test-Path -LiteralPath $metadataPath)) {
        Write-Host "No ATDR launcher-managed processes are recorded. Nothing was stopped."
        Write-Host "  Status: .\scripts\check_system.cmd"
        Write-Host "  Start: .\scripts\start_system.cmd"
        exit 0
    }
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    $stopped = 0
    $records = @($metadata.processes)
    [array]::Reverse($records)
    foreach ($record in $records) {
        $process = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
        if ($null -eq $process) { continue }
        $recorded = [datetime]::Parse([string]$record.started_at).ToUniversalTime()
        $actual = $process.StartTime.ToUniversalTime()
        if ([math]::Abs(($actual - $recorded).TotalSeconds) -gt 5) {
            Write-Warning "Skipped PID $($record.pid): start time does not match launcher metadata."
            continue
        }
        Stop-Process -Id $process.Id -Force
        $stopped += 1
        Write-Host "Stopped $($record.name) (PID $($process.Id))."
    }
    Remove-Item -LiteralPath $metadataPath -Force
    Write-Host "ATDR system stop complete. Processes stopped: $stopped" -ForegroundColor Green
    Write-Host "  Restart: .\scripts\start_system.cmd"
}
catch {
    [Console]::Error.WriteLine("ATDR shutdown failed safely: $($_.Exception.Message)")
    exit 1
}
