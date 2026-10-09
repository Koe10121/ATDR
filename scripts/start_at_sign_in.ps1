[CmdletBinding()]
param(
    [int]$Attempts = 5,
    [int]$WaitSeconds = 30
)

# Run at Windows sign-in by the entry that scripts\autostart.cmd installs. Starts ATDR the normal way, without
# opening a browser, and tries again while Windows is still bringing up what ATDR needs (the MongoDB service for
# the MFU sign-in shell). Writes what happened to .atdr_runtime\logs\autostart.log. Then it makes sure the watcher
# (scripts\watch_system.ps1) is running, which keeps ATDR's parts running from then on.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

$logDir = Join-Path (Get-AtdrRuntimeDirectory) "logs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir "autostart.log"

function Write-AutostartLog {
    param([string]$Message)
    Add-Content -LiteralPath $log -Value "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) $Message" -Encoding UTF8
}

function Start-Watcher {
    if (-not (Start-AtdrWatcherTask)) { Write-AutostartLog "The watcher is not installed (scripts\autostart.cmd installs it); a part that stops will stay stopped." }
}

Write-AutostartLog "Sign-in start requested."
# A stop with -HoldHours is meant to outlast a sign-in (a rebuild or a restore is under way).
$desired = Read-AtdrDesiredState
if (Test-AtdrHeld $desired) {
    Write-AutostartLog "ATDR is being kept stopped until $($desired.hold_until.ToLocalTime().ToString('yyyy-MM-dd HH:mm')) (stop_system -HoldHours); not started."
    Start-Watcher
    exit 0
}
# Both before the first try, not after the last. Windows has ended this script seconds after a real sign-in
# (three sign-ins of three); from here on, whatever happens to it, ATDR is meant to run and the watcher goes on
# starting it.
Set-AtdrDesiredState -State "running" -By "start_at_sign_in"
Start-Watcher
for ($attempt = 1; $attempt -le [Math]::Max(1, $Attempts); $attempt++) {
    if ((Test-HttpEndpoint -Url "http://127.0.0.1:8000/health/live" -TimeoutSeconds 3).reachable) {
        Write-AutostartLog "ATDR is already running; nothing to start."
        exit 0
    }
    # The start script's output goes to files, and only the script itself is waited for. Read through a pipe, or
    # waited for with Start-Process -Wait, this would never return: ATDR's own processes keep the pipe open and
    # count as descendants, so Windows would see the sign-in task as still running and stop it, and ATDR with it,
    # at the task's time limit.
    $out = Join-Path $logDir "autostart.start.out.log"
    $err = Join-Path $logDir "autostart.start.err.log"
    $start = Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$(Join-Path $PSScriptRoot 'start_system.ps1')`"", "-NoBrowser"
    ) -WorkingDirectory (Get-AtdrProjectRoot) -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    # Without its handle held from the start, PowerShell has no exit code for the process once it has ended.
    $null = $start.Handle
    $start.WaitForExit()
    $code = $start.ExitCode
    foreach ($file in @($out, $err)) {
        $text = if (Test-Path -LiteralPath $file) { (Get-Content -LiteralPath $file -Raw -ErrorAction SilentlyContinue) } else { "" }
        if ($text -and $text.Trim()) { Add-Content -LiteralPath $log -Value $text.TrimEnd() -Encoding UTF8 }
    }
    if ($code -eq 0) {
        Write-AutostartLog "ATDR started (attempt $attempt)."
        exit 0
    }
    if ($code -eq 3) {
        # The watcher got there first; the look at the top of this loop will find ATDR running.
        Write-AutostartLog "Another start is under way (attempt $attempt)."
    }
    else {
        Write-AutostartLog "Start attempt $attempt of $Attempts failed with exit code $code."
    }
    if ($attempt -lt $Attempts) { Start-Sleep -Seconds ([Math]::Max(1, $WaitSeconds)) }
}
Write-AutostartLog "ATDR did not start. Run scripts\start_system.cmd to see why. The watcher goes on trying every few minutes."
exit 1
