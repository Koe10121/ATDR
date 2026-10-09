[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$Status
)

# ATDR neither starts by itself after a restart nor brings back a part that stops. This installs (or with -Remove
# takes away) two entries for this Windows user:
#   - "ATDR start at sign-in": starts ATDR when the user signs in (scripts\start_at_sign_in.ps1). A scheduled task
#     when Windows lets this user register one, else a shortcut in the user's Startup folder.
#   - "ATDR keep running": the watcher (scripts\watch_system.ps1), which restarts a part that stopped. Windows
#     looks every minute whether it is running and starts it when it is not; while it runs, nothing is launched.
# Both run hidden. No password is stored, and nothing starts before someone signs in.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

$taskName = "ATDR start at sign-in"
$watchTaskName = $AtdrWatcherTaskName
$root = Get-AtdrProjectRoot
$launcher = Join-Path $PSScriptRoot "start_at_sign_in.ps1"
$watcher = Join-Path $PSScriptRoot "watch_system.ps1"
$arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$launcher`""
$watchArguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$watcher`""
# A task's PowerShell is given no console window at all (conhost --headless). With a window, even a hidden one, the
# sign-in start was ended by Windows seconds after each real sign-in (task result 0xC000013A, on three sign-ins of
# three), and the watcher once ended when the session was unlocked.
$headless = Join-Path $env:SystemRoot "System32\conhost.exe"
function New-HiddenPowerShellAction {
    param([string]$PowerShellArguments)
    if (Test-Path -LiteralPath $headless -PathType Leaf) {
        return New-ScheduledTaskAction -Execute $headless -Argument "--headless powershell.exe $PowerShellArguments" -WorkingDirectory $root
    }
    return New-ScheduledTaskAction -Execute "powershell.exe" -Argument $PowerShellArguments -WorkingDirectory $root
}
$shortcutPath = Join-Path ([Environment]::GetFolderPath("Startup")) "ATDR start at sign-in.lnk"

function Get-AutostartState {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $watch = Get-ScheduledTask -TaskName $watchTaskName -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        task = $null -ne $task
        shortcut = Test-Path -LiteralPath $shortcutPath -PathType Leaf
        watcher = $null -ne $watch
        watcher_running = ($null -ne $watch -and [string]$watch.State -eq "Running")
    }
}

function Write-AutostartState {
    $state = Get-AutostartState
    if ($state.task) { Write-Host "ATDR starts at sign-in: scheduled task '$taskName'." -ForegroundColor Green }
    if ($state.shortcut) { Write-Host "ATDR starts at sign-in: Startup folder shortcut '$shortcutPath'." -ForegroundColor Green }
    if (-not $state.task -and -not $state.shortcut) { Write-Host "ATDR does not start at sign-in. Start it with scripts\start_system.cmd." }
    Write-Host "  What each sign-in start did: .atdr_runtime\logs\autostart.log"
    if ($state.watcher) {
        Write-Host "ATDR restarts a part that stops: scheduled task '$watchTaskName' ($(if ($state.watcher_running) { 'watching now' } else { 'not running; it starts within a minute' }))." -ForegroundColor Green
    }
    else {
        Write-Host "ATDR does not restart a part that stops (no task '$watchTaskName')." -ForegroundColor Yellow
    }
    Write-Host "  What the watcher did: .atdr_runtime\logs\watch.log"
}

if ($Status) {
    Write-AutostartState
    exit 0
}

if ($Remove) {
    $state = Get-AutostartState
    if ($state.watcher) {
        # The task goes first, or it would start the watcher again within the minute.
        Unregister-ScheduledTask -TaskName $watchTaskName -Confirm:$false
    }
    [void](Stop-AtdrWatcherProcess)
    if ($state.task) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
    if ($state.shortcut) { Remove-Item -LiteralPath $shortcutPath -Force }
    Write-AutostartState
    exit 0
}

if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw "scripts\start_at_sign_in.ps1 is missing." }
if (-not (Test-Path -LiteralPath $watcher -PathType Leaf)) { throw "scripts\watch_system.ps1 is missing." }

$registered = $false
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
try {
    $action = New-HiddenPowerShellAction $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    # Windows services ATDR needs (MongoDB) are still starting in the first seconds after sign-in.
    $trigger.Delay = "PT45S"
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Starts ATDR when this user signs in (scripts\start_at_sign_in.ps1). Remove with scripts\autostart.cmd -Remove." -Force -ErrorAction Stop | Out-Null
    $registered = $true
}
catch {
    Write-Host "Windows did not let this user register a sign-in task ($($_.Exception.Message.Trim())); using the Startup folder instead." -ForegroundColor Yellow
}

if ($registered) {
    # One entry only: an older Startup shortcut would start ATDR a second time.
    if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) { Remove-Item -LiteralPath $shortcutPath -Force }
}
else {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = (Get-Command powershell.exe).Source
    $shortcut.Arguments = $arguments
    $shortcut.WorkingDirectory = $root
    $shortcut.WindowStyle = 7
    $shortcut.Description = "Starts ATDR when this user signs in. Remove with scripts\autostart.cmd -Remove."
    $shortcut.Save()
}

try {
    # A watcher from an earlier install goes on running under the action it was started with; end it, so the one
    # that follows is started as this install says.
    [void](Stop-AtdrWatcherProcess)
    $watchAction = New-HiddenPowerShellAction $watchArguments
    # Every minute, for good. While the watcher runs a new start is ignored (IgnoreNew), so nothing is launched and
    # no window opens; when it has ended, the next minute starts it again. Windows' own "restart a failed task"
    # does not do this: tried on this laptop, a watcher that was killed stayed down.
    $watchTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
    # No time limit: the watcher is meant to run for as long as the user is signed in.
    $watchSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
    $watchPrincipal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $watchTaskName -Action $watchAction -Trigger $watchTrigger -Settings $watchSettings -Principal $watchPrincipal -Description "Keeps ATDR running: restarts a part that stopped (scripts\watch_system.ps1). Remove with scripts\autostart.cmd -Remove." -Force -ErrorAction Stop | Out-Null
    # Watching from now, not from the trigger's first minute. (Windows needs a moment to see that the watcher
    # which was just ended is gone.)
    for ($waited = 0; $waited -lt 10 -and [string](Get-ScheduledTask -TaskName $watchTaskName).State -eq "Running"; $waited++) { Start-Sleep -Milliseconds 500 }
    [void](Start-AtdrWatcherTask)
}
catch {
    Write-Host "Windows did not let this user register the watcher task ($($_.Exception.Message.Trim())). ATDR will start at sign-in but will not restart a part that stops." -ForegroundColor Yellow
}
Write-AutostartState
