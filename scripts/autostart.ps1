[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$Status
)

# ATDR does not start by itself after a restart. This installs (or with -Remove takes away) one entry that starts it
# when this Windows user signs in:
#   - a scheduled task "ATDR start at sign-in", when Windows lets this user register one; or
#   - a shortcut in the user's Startup folder, when it does not (a sign-in task usually needs an administrator).
# Both run scripts\start_at_sign_in.ps1 hidden. No password is stored, and nothing starts before someone signs in.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

$taskName = "ATDR start at sign-in"
$root = Get-AtdrProjectRoot
$launcher = Join-Path $PSScriptRoot "start_at_sign_in.ps1"
$arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$launcher`""
$shortcutPath = Join-Path ([Environment]::GetFolderPath("Startup")) "ATDR start at sign-in.lnk"

function Get-AutostartState {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        task = $null -ne $task
        shortcut = Test-Path -LiteralPath $shortcutPath -PathType Leaf
    }
}

function Write-AutostartState {
    $state = Get-AutostartState
    if ($state.task) { Write-Host "ATDR starts at sign-in: scheduled task '$taskName'." -ForegroundColor Green }
    if ($state.shortcut) { Write-Host "ATDR starts at sign-in: Startup folder shortcut '$shortcutPath'." -ForegroundColor Green }
    if (-not $state.task -and -not $state.shortcut) { Write-Host "ATDR does not start at sign-in. Start it with scripts\start_system.cmd." }
    Write-Host "  What each sign-in start did: .atdr_runtime\logs\autostart.log"
}

if ($Status) {
    Write-AutostartState
    exit 0
}

if ($Remove) {
    $state = Get-AutostartState
    if ($state.task) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
    if ($state.shortcut) { Remove-Item -LiteralPath $shortcutPath -Force }
    Write-AutostartState
    exit 0
}

if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw "scripts\start_at_sign_in.ps1 is missing." }

$registered = $false
try {
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments -WorkingDirectory $root
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
Write-AutostartState
