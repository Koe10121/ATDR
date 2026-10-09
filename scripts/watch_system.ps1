[CmdletBinding()]
param(
    [int]$IntervalSeconds = 30,
    # Make this many checks and end. 0 keeps watching; a test or a person asks for one.
    [int]$Checks = 0
)

# Keeps ATDR running. While ATDR is meant to run (it was started with start_system and not stopped with
# stop_system) this script looks at its parts every half minute and
#   - starts a part whose process has gone;
#   - stops and starts a part that is running but has not answered for three minutes;
#   - starts everything when nothing is running (a start at sign-in that failed, a hold that ran out).
# A part that keeps dying is tried three times in ten minutes, then once every five. Each check is written to
# .atdr_runtime\watch-status.json, which the dashboard's System panel reads, and each action to
# .atdr_runtime\logs\watch.log. The task "ATDR keep running" (scripts\autostart.cmd) runs this and starts it again
# within a minute if it ever ends.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

$runtime = Get-AtdrRuntimeDirectory
$logDir = Join-Path $runtime "logs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir "watch.log"
$lockPath = Join-Path $runtime "watch.lock"

function Write-WatchLog {
    param([string]$Message)
    Add-Content -LiteralPath $log -Value "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) $Message" -Encoding UTF8
}

# One watcher only: two would each restart the same part.
if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
    try {
        if (Test-TrackedProcessRecordActive (Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json)) { exit 0 }
    }
    catch { }
}
$me = Get-Process -Id $PID
$watcherStarted = $me.StartTime.ToUniversalTime()
[ordered]@{ pid = $PID; started_at = $watcherStarted.ToString("o") } | ConvertTo-Json | Set-Content -LiteralPath $lockPath -Encoding UTF8

$unanswered = @{}
$restarts = @{}
$lastAction = $null
$assistantLooked = [datetime]::MinValue

# What the watcher before this one had restarted still counts, so a part that keeps dying is not tried afresh.
try {
    $before = Read-AtdrWatchStatus
    if ($null -ne $before) {
        foreach ($part in @($before.status.parts)) {
            $times = @(@($part.restarts) | ForEach-Object { ConvertTo-AtdrUtc $_ } | Where-Object { $null -ne $_ })
            if ($times.Count) { $restarts[[string]$part.name] = $times }
        }
        $times = @(@($before.status.all_restarts) | ForEach-Object { ConvertTo-AtdrUtc $_ } | Where-Object { $null -ne $_ })
        if ($times.Count) { $restarts["*"] = $times }
        # And what was last done: the System panel goes on saying it until this watcher has to act itself.
        $lastAction = $before.status.last_action
    }
}
catch {
    # A status file from an older version, or a damaged one: start counting afresh.
    $restarts = @{}
    $lastAction = $null
}

function Invoke-AtdrStart {
    # Runs the start script and waits for it alone (its output goes to files: see start_at_sign_in.ps1).
    param([string[]]$Only = @())
    $out = Join-Path $logDir "watch.start.out.log"
    $err = Join-Path $logDir "watch.start.err.log"
    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$(Join-Path $PSScriptRoot 'start_system.ps1')`"", "-NoBrowser")
    if ($Only.Count) { $arguments += @("-Only", ($Only -join ",")) }
    $start = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -WorkingDirectory (Get-AtdrProjectRoot) -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    $null = $start.Handle
    $start.WaitForExit()
    $said = ""
    foreach ($file in @($err, $out)) {
        if (-not $said -and (Test-Path -LiteralPath $file)) {
            $text = Get-Content -LiteralPath $file -Raw -ErrorAction SilentlyContinue
            if ($text -and $text.Trim()) { $said = ($text.Trim() -split "`r?`n")[-1] }
        }
    }
    return [pscustomobject]@{ ok = ($start.ExitCode -eq 0); code = $start.ExitCode; said = $said }
}

function Add-AtdrRestart {
    param([string]$Name, [datetime]$Now)
    $kept = @(@($restarts[$Name]) | Where-Object { $null -ne $_ -and ($Now - $_).TotalHours -lt 24 })
    $restarts[$Name] = @($kept + $Now)
}

function Invoke-AtdrWatchCheck {
    $now = (Get-Date).ToUniversalTime()
    $root = Get-AtdrProjectRoot
    $envValues = Read-DotEnvFile (Join-Path $root ".env")
    $desired = Read-AtdrDesiredState
    $expected = @(Get-AtdrExpectedParts $envValues)

    $records = @()
    $metadataPath = Join-Path $runtime "system-processes.json"
    if (Test-Path -LiteralPath $metadataPath) {
        try { $records = @((Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json).processes) } catch { $records = @() }
    }
    $aliveRecords = @($records | Where-Object { Test-TrackedProcessRecordActive $_ })
    $alive = @($aliveRecords | ForEach-Object { [string]$_.name })
    $startedAt = @{}
    foreach ($record in $aliveRecords) { $startedAt[[string]$record.name] = ConvertTo-AtdrUtc $record.started_at }

    $answering = @{}
    foreach ($name in $alive) {
        $address = Get-AtdrPartAddress $name
        if (-not $address) { continue }
        $answering[$name] = [bool](Test-HttpEndpoint -Url $address -TimeoutSeconds 5).reachable
        $unanswered[$name] = if ($answering[$name]) { 0 } else { 1 + $(if ($unanswered.ContainsKey($name)) { [int]$unanswered[$name] } else { 0 }) }
    }
    foreach ($name in @($unanswered.Keys)) { if ($name -notin $alive) { $unanswered.Remove($name) } }

    $decision = Get-AtdrWatchDecision -DesiredState $desired.state -HoldUntil $desired.hold_until -Now $now `
        -Expected $expected -Alive $alive -Unanswered $unanswered -StartedAt $startedAt -Restarts $restarts
    if ($decision.resume) {
        Set-AtdrDesiredState -State "running" -By "watch_system: the time it was to stay stopped had passed"
        $desired = Read-AtdrDesiredState
    }

    if ($decision.action -eq "start_all") {
        Write-WatchLog "Starting ATDR: $($decision.reason)."
        $result = Invoke-AtdrStart
        if ($result.code -eq 3) {
            # The sign-in start is at it (exit code 3 is the start script's "another start holds the lock").
            Write-WatchLog "Another start of ATDR is under way; left to it."
        }
        else {
            Add-AtdrRestart "*" $now
            $script:lastAction = [ordered]@{ at = $now.ToString("o"); all = $true; resumed = [bool]$decision.resume; started = @(); restarted = @(); ok = $result.ok; said = $result.said }
            Write-WatchLog $(if ($result.ok) { "ATDR started." } else { "ATDR did not start (exit code $($result.code)): $($result.said)" })
        }
    }
    elseif ($decision.action -eq "parts") {
        foreach ($name in @($decision.restart)) {
            # Running but silent: it is stopped first, by the record the start script made for it.
            $record = @($aliveRecords | Where-Object { [string]$_.name -eq $name } | Select-Object -First 1)
            if ($record.Count) { Stop-Process -Id ([int]$record[0].pid) -Force -ErrorAction SilentlyContinue }
            $unanswered.Remove($name)
        }
        $names = @(@($decision.start) + @($decision.restart))
        Write-WatchLog "Starting $($names -join ', ') ($($decision.reason))."
        Start-Sleep -Milliseconds 500
        $result = Invoke-AtdrStart -Only $names
        if ($result.code -eq 3) {
            Write-WatchLog "Another start of ATDR is under way; left to it."
        }
        else {
            foreach ($name in $names) { Add-AtdrRestart $name $now }
            $script:lastAction = [ordered]@{ at = $now.ToString("o"); all = $false; resumed = $false; started = @($decision.start); restarted = @($decision.restart); ok = $result.ok; said = $result.said }
            Write-WatchLog $(if ($result.ok) { "Started $($names -join ', ')." } else { "Could not start $($names -join ', ') (exit code $($result.code)): $($result.said)" })
        }
    }

    # The SOC Assistant's model is not one of ATDR's parts, but ATDR is the one that needs it.
    if ($desired.state -eq "running" -and ($now - $assistantLooked).TotalMinutes -ge 5) {
        $script:assistantLooked = $now
        try { [void](Start-AssistantModelIfStopped $envValues) } catch { }
    }

    # Read again after acting, so the status shows what is true now.
    $records = @()
    if (Test-Path -LiteralPath $metadataPath) {
        try { $records = @((Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json).processes) } catch { $records = @() }
    }
    $aliveNow = @{}
    foreach ($record in @($records | Where-Object { Test-TrackedProcessRecordActive $_ })) { $aliveNow[[string]$record.name] = $record }
    $parts = @(foreach ($name in $expected) {
        $times = @(@($restarts[$name]) | Where-Object { $null -ne $_ -and ($now - $_).TotalHours -lt 24 })
        [ordered]@{
            name = $name
            running = $aliveNow.ContainsKey($name)
            started_at = if ($aliveNow.ContainsKey($name)) { [string]$aliveNow[$name].started_at } else { $null }
            answering = if ($answering.ContainsKey($name) -and $aliveNow.ContainsKey($name)) { $answering[$name] } else { $null }
            unanswered_checks = if ($unanswered.ContainsKey($name)) { [int]$unanswered[$name] } else { 0 }
            keeps_stopping = ($name -in @($decision.waiting))
            restarts = @($times | ForEach-Object { $_.ToString("o") })
        }
    })
    $allTimes = @(@($restarts["*"]) | Where-Object { $null -ne $_ -and ($now - $_).TotalHours -lt 24 })
    $status = [ordered]@{
        version = 1
        watcher = [ordered]@{ pid = $PID; started_at = $watcherStarted.ToString("o"); checked_at = (Get-Date).ToUniversalTime().ToString("o"); interval_seconds = $IntervalSeconds }
        desired = [ordered]@{
            state = $desired.state
            since = if ($null -ne $desired.since) { $desired.since.ToString("o") } else { $null }
            by = $desired.by
            hold_until = if ($null -ne $desired.hold_until) { $desired.hold_until.ToString("o") } else { $null }
        }
        note = [string]$decision.reason
        parts = $parts
        all_restarts = @($allTimes | ForEach-Object { $_.ToString("o") })
        last_action = $script:lastAction
    }
    # Written whole, then moved into place: the dashboard never reads half a file.
    $statusPath = Get-AtdrWatchStatusPath
    $arriving = "$statusPath.arriving"
    $status | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $arriving -Encoding UTF8
    Move-Item -LiteralPath $arriving -Destination $statusPath -Force
}

Write-WatchLog "Watching ATDR (PID $PID, a check every $IntervalSeconds s)."
$made = 0
try {
    while ($true) {
        $made += 1
        try {
            Invoke-AtdrWatchCheck
        }
        catch {
            Write-WatchLog "A check failed: $($_.Exception.Message)"
        }
        if ($Checks -gt 0 -and $made -ge $Checks) { break }
        Start-Sleep -Seconds ([Math]::Max(1, $IntervalSeconds))
    }
}
finally {
    try {
        $held = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
        if ([int]$held.pid -eq $PID) { Remove-Item -LiteralPath $lockPath -Force }
    }
    catch { }
}
