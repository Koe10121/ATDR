[CmdletBinding()]
param(
    # Keep ATDR stopped for this many hours, across a sign-in too, unless it is started by hand. For work that
    # needs it down (a rebuild, a restore): without this a sign-in starts ATDR again. After that time the watcher
    # starts it, so a stop that was forgotten does not last.
    [double]$HoldHours = 0,
    # Stop only these parts; the others keep running and stay on record. A release stops ATDR's own parts this way
    # and leaves the MFU sign-in page up. ATDR as a whole still counts as stopped, so the watcher starts nothing.
    [string[]]$Only = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

# Given through -File, a list of names arrives as one text with commas.
$Only = @($Only | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

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
    $liveCopy = Get-AtdrLiveCopy
    $elsewhere = if ($liveCopy) { "  This is the folder ATDR is developed in. ATDR itself runs from $liveCopy; stop it there." } else { $null }
    if (-not (Test-Path -LiteralPath $metadataPath)) {
        Write-Host "No ATDR launcher-managed processes are recorded. Nothing was stopped."
        Write-Host "  Status: .\scripts\check_system.cmd"
        Write-Host "  Start: .\scripts\start_system.cmd"
        if ($null -ne $holdUntil) { Write-Host $afterwards }
        if ($elsewhere) { Write-Host $elsewhere -ForegroundColor Yellow }
        exit 0
    }
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    $stopped = 0
    $records = @($metadata.processes)
    # With -Only: the parts that are left running. They stay on record, or nothing could find them afterwards.
    $kept = @($records | Where-Object { $Only.Count -and [string]$_.name -notin $Only -and (Test-TrackedProcessRecordActive $_) })
    [array]::Reverse($records)
    foreach ($record in $records) {
        if ($Only.Count -and [string]$record.name -notin $Only) { continue }
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
    if ($kept.Count) {
        [ordered]@{
            version = 1
            started_at = [string]$metadata.started_at
            processes = @($kept)
            secrets_stored = $false
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
        Write-Host "Stopped $stopped of ATDR's parts; still running: $(@($kept | ForEach-Object { [string]$_.name }) -join ', ')." -ForegroundColor Green
    }
    else {
        Remove-Item -LiteralPath $metadataPath -Force
        Write-Host "ATDR system stop complete. Processes stopped: $stopped" -ForegroundColor Green
    }
    Write-Host $afterwards
    if ($elsewhere) { Write-Host $elsewhere -ForegroundColor Yellow }
}
catch {
    [Console]::Error.WriteLine("ATDR shutdown failed safely: $($_.Exception.Message)")
    exit 1
}
