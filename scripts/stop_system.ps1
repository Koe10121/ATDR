[CmdletBinding()]
param(
    # Keep ATDR stopped for this many hours, across a sign-in too, unless it is started by hand. For work that
    # needs it down (a rebuild, a restore): without this a sign-in starts ATDR again. After that time the watcher
    # starts it, so a stop that was forgotten does not last.
    [double]$HoldHours = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

try {
    # On record before anything is stopped: the watcher must not bring a part back while this script stops them.
    $holdUntil = if ($HoldHours -gt 0) { (Get-Date).ToUniversalTime().AddHours($HoldHours) } else { $null }
    Set-AtdrDesiredState -State "stopped" -By "stop_system" -HoldUntil $holdUntil
    # A start that is under way finishes first; stopping half of what it is still launching leaves strays.
    for ($waited = 0; $waited -lt 90 -and (Test-AtdrStartLockHeld); $waited++) { Start-Sleep -Seconds 1 }

    $afterwards = if ($null -ne $holdUntil) {
        "  ATDR stays stopped until $($holdUntil.ToLocalTime().ToString('yyyy-MM-dd HH:mm')), also across a sign-in. Start it sooner: .\scripts\start_system.cmd"
    }
    else {
        "  Restart: .\scripts\start_system.cmd"
    }
    $metadataPath = Join-Path (Get-AtdrRuntimeDirectory) "system-processes.json"
    if (-not (Test-Path -LiteralPath $metadataPath)) {
        Write-Host "No ATDR launcher-managed processes are recorded. Nothing was stopped."
        Write-Host "  Status: .\scripts\check_system.cmd"
        Write-Host "  Start: .\scripts\start_system.cmd"
        if ($null -ne $holdUntil) { Write-Host $afterwards }
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
    Write-Host $afterwards
}
catch {
    [Console]::Error.WriteLine("ATDR shutdown failed safely: $($_.Exception.Message)")
    exit 1
}
