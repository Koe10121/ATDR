[CmdletBinding()]
param(
    [int]$IntervalSeconds = 2,
    # Make this many looks and end. 0 keeps looking; a test or a person asks for one.
    [int]$Checks = 0,
    # What shows one notification. A test names a script that only writes down what it was given.
    [string]$ShowScript = ""
)

# ATDR's helper on the desktop of whoever is signed in. Where ATDR runs without a sign-in
# (scripts\autostart.cmd -BeforeSignIn) its parts have no desktop: they cannot show a Windows notification and
# cannot start an app that lives in the notification area. This script, which the task "ATDR at the desktop" runs
# in the sign-in session, does those two things for them:
#   - a notification a part left in .atdr_runtime\desktop-notifications is shown, and the part is told that it was
#     (the file <id>.json becomes <id>.shown, or <id>.failed);
#   - the SOC Assistant's Ollama app is started when it is not running (looked at every five minutes).
# It starts nothing of ATDR itself and stops nothing. Windows starts it again within a minute if it ever ends.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

if (-not $ShowScript) { $ShowScript = Join-Path $PSScriptRoot "show_notification.ps1" }
$runtime = Get-AtdrRuntimeDirectory
$logDir = Join-Path $runtime "logs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir "desktop.log"
$lockPath = Join-Path $runtime "desktop.lock"
$queue = Get-AtdrDesktopQueuePath
# A notification nobody collected (the part that asked gave up waiting) is cleared away after this long.
$staleAfterMinutes = 10

function Write-DesktopLog {
    param([string]$Message)
    Add-Content -LiteralPath $log -Value "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) $Message" -Encoding UTF8
}

# One helper only: two would each show the same notification.
if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
    try {
        if (Test-TrackedProcessRecordActive (Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json)) { exit 0 }
    }
    catch { }
}
$me = Get-Process -Id $PID
[ordered]@{ pid = $PID; started_at = $me.StartTime.ToUniversalTime().ToString("o") } | ConvertTo-Json | Set-Content -LiteralPath $lockPath -Encoding UTF8

function Show-AtdrWaitingNotifications {
    if (-not (Test-Path -LiteralPath $queue -PathType Container)) { return }
    foreach ($file in @(Get-ChildItem -LiteralPath $queue -Filter "*.json" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc)) {
        $showing = Join-Path $queue ($file.BaseName + ".showing")
        # Taken by renaming: the part that asked sees its file gone and knows someone has it.
        try { Move-Item -LiteralPath $file.FullName -Destination $showing -ErrorAction Stop } catch { continue }
        $outcome = "failed"
        try {
            $words = Get-Content -LiteralPath $showing -Raw | ConvertFrom-Json
            $env:ATDR_NOTIFICATION_TITLE = [string]$words.ATDR_NOTIFICATION_TITLE
            $env:ATDR_NOTIFICATION_BODY = [string]$words.ATDR_NOTIFICATION_BODY
            $env:ATDR_NOTIFICATION_LINK = [string]$words.ATDR_NOTIFICATION_LINK
            & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ShowScript *> $null
            if ($LASTEXITCODE -eq 0) { $outcome = "shown" } else { Write-DesktopLog "A notification could not be shown (the script ended with $LASTEXITCODE)." }
        }
        catch {
            Write-DesktopLog "A notification could not be shown: $($_.Exception.Message)"
        }
        finally {
            Remove-Item Env:ATDR_NOTIFICATION_TITLE, Env:ATDR_NOTIFICATION_BODY, Env:ATDR_NOTIFICATION_LINK -ErrorAction SilentlyContinue
        }
        try { Move-Item -LiteralPath $showing -Destination (Join-Path $queue ($file.BaseName + ".$outcome")) -Force -ErrorAction Stop } catch { }
    }
    # What the asking part never collected.
    $old = (Get-Date).ToUniversalTime().AddMinutes(-$staleAfterMinutes)
    foreach ($left in @(Get-ChildItem -LiteralPath $queue -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @(".shown", ".failed", ".showing", ".arriving") -and $_.LastWriteTimeUtc -lt $old })) {
        Remove-Item -LiteralPath $left.FullName -Force -ErrorAction SilentlyContinue
    }
}

Write-DesktopLog "At the desktop (PID $PID): showing ATDR's notifications."
$made = 0
$assistantLooked = [datetime]::MinValue
try {
    while ($true) {
        $made += 1
        try {
            Show-AtdrWaitingNotifications
            if (((Get-Date) - $assistantLooked).TotalMinutes -ge 5) {
                $assistantLooked = Get-Date
                # Only while ATDR is meant to run: nobody needs the model beside a stopped ATDR.
                if ((Read-AtdrDesiredState).state -eq "running") {
                    try { [void](Start-AssistantModelIfStopped (Read-DotEnvFile (Join-Path (Get-AtdrProjectRoot) ".env"))) } catch { }
                }
            }
        }
        catch {
            Write-DesktopLog "A look failed: $($_.Exception.Message)"
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
