[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$Status,
    # Start ATDR with the machine, before anyone signs in, and keep it running when they sign out. Windows asks for
    # an administrator once ("Do you want to allow this app to make changes?").
    [switch]$BeforeSignIn,
    # Back to starting at sign-in, on a machine where ATDR starts with the machine. Without either switch the way
    # that is installed stays; where nothing is installed yet, that is at sign-in.
    [switch]$AtSignIn,
    # On mains power, do not let the machine go to sleep by itself. Closing the lid still puts it to sleep, and on
    # battery nothing changes. Without this switch the sleep times are left as they are. Given alone where ATDR is
    # installed already, it changes only that.
    [switch]$StayAwakeOnMains,
    # The half of an install that runs with administrator rights. Not for a person to give.
    [switch]$Elevated,
    [string]$ForUser = "",
    [string]$LogTo = ""
)

# ATDR neither starts by itself after a restart nor brings back a part that stops. This installs (or with -Remove
# takes away) the entries that do, for this Windows user. There are two ways.
#
# For a sign-in (no switch). Nothing runs before someone signs in, and everything ends when they sign out:
#   - "ATDR start at sign-in": starts ATDR when the user signs in (scripts\start_at_sign_in.ps1). A scheduled task
#     when Windows lets this user register one, else a shortcut in the user's Startup folder.
#   - "ATDR keep running": the watcher (scripts\watch_system.ps1), which restarts a part that stopped. Windows
#     looks every minute whether it is running and starts it when it is not; while it runs, nothing is launched.
#
# With the machine (-BeforeSignIn). ATDR runs whether or not anyone is signed in:
#   - "ATDR keep running" is started by Windows with the machine and runs without a sign-in, as this user and
#     without administrator rights. It makes every start of ATDR, so the parts belong to it and not to a sign-in.
#   - "ATDR start at sign-in" stays: a sign-in still ends a stop. It starts nothing itself any more.
#   - "ATDR at the desktop" (scripts\desktop_agent.ps1) runs in the sign-in session and shows ATDR's Windows
#     notifications, which a part without a desktop cannot.
# Registering a task that runs without a sign-in needs administrator rights, and so does changing or removing one
# afterwards. No password is stored either way.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "system_common.ps1")

$taskName = $AtdrSignInTaskName
$watchTaskName = $AtdrWatcherTaskName
$desktopTaskName = $AtdrDesktopTaskName
$root = Get-AtdrProjectRoot
$launcher = Join-Path $PSScriptRoot "start_at_sign_in.ps1"
$watcher = Join-Path $PSScriptRoot "watch_system.ps1"
$desktop = Join-Path $PSScriptRoot "desktop_agent.ps1"
$arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$launcher`""
$watchArguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$watcher`""
$desktopArguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$desktop`""
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
    $helper = Get-ScheduledTask -TaskName $desktopTaskName -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        task = $null -ne $task
        shortcut = Test-Path -LiteralPath $shortcutPath -PathType Leaf
        watcher = $null -ne $watch
        watcher_running = ($null -ne $watch -and [string]$watch.State -eq "Running")
        # Whether Windows starts the watcher without anyone being signed in.
        without_sign_in = ($null -ne $watch -and [string]$watch.Principal.LogonType -eq "S4U")
        desktop = $null -ne $helper
        desktop_running = ($null -ne $helper -and [string]$helper.State -eq "Running")
    }
}

function Write-AutostartState {
    $state = Get-AutostartState
    if ((Test-AtdrRunsWithoutSignIn) -and -not $state.watcher) {
        Write-Host "This folder is on record as starting with the machine, but the task '$watchTaskName' is not there, or this window may not read it. scripts\autostart.cmd -BeforeSignIn registers it again." -ForegroundColor Yellow
    }
    elseif ($state.without_sign_in) {
        Write-Host "ATDR starts with the machine, before anyone signs in, and keeps running when they sign out: scheduled task '$watchTaskName' ($(if ($state.watcher_running) { 'watching now' } else { 'not running; it starts within a minute' }))." -ForegroundColor Green
        if ($state.desktop) {
            Write-Host "Its Windows notifications are shown by the task '$desktopTaskName' ($(if ($state.desktop_running) { 'running' } else { 'not running; it starts within a minute of a sign-in' }))." -ForegroundColor Green
        }
        else {
            Write-Host "No task '$desktopTaskName': ATDR's Windows notifications are not shown." -ForegroundColor Yellow
        }
    }
    else {
        if ($state.task) { Write-Host "ATDR starts at sign-in: scheduled task '$taskName'." -ForegroundColor Green }
        if ($state.shortcut) { Write-Host "ATDR starts at sign-in: Startup folder shortcut '$shortcutPath'." -ForegroundColor Green }
        if (-not $state.task -and -not $state.shortcut) { Write-Host "ATDR does not start at sign-in. Start it with scripts\start_system.cmd." }
        if ($state.watcher) {
            Write-Host "ATDR restarts a part that stops: scheduled task '$watchTaskName' ($(if ($state.watcher_running) { 'watching now' } else { 'not running; it starts within a minute' }))." -ForegroundColor Green
            Write-Host "  Nothing runs before someone signs in, and everything ends when they sign out. scripts\autostart.cmd -BeforeSignIn changes that."
        }
        else {
            Write-Host "ATDR does not restart a part that stops (no task '$watchTaskName')." -ForegroundColor Yellow
        }
    }
    $sleep = Get-AtdrMainsSleepSeconds
    if ($null -ne $sleep) {
        if ($sleep -eq 0) { Write-Host "On mains power this machine does not go to sleep by itself." -ForegroundColor Green }
        else { Write-Host "On mains power this machine goes to sleep after $([int][Math]::Round($sleep / 60)) minutes without use, and ATDR pauses with it. scripts\autostart.cmd -StayAwakeOnMains changes that." -ForegroundColor Yellow }
    }
    Write-Host "  What each sign-in start did: .atdr_runtime\logs\autostart.log"
    Write-Host "  What the watcher did: .atdr_runtime\logs\watch.log"
}

function Save-AtdrAutostartRecord {
    # What this script installed, kept beside the other records of this folder. Later runs add to it.
    param([hashtable]$Values)
    $kept = [ordered]@{}
    $path = Get-AtdrAutostartRecordPath
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        try {
            $before = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            foreach ($property in $before.PSObject.Properties) { $kept[$property.Name] = $property.Value }
        }
        catch { }
    }
    foreach ($name in $Values.Keys) { $kept[$name] = $Values[$name] }
    New-Item -ItemType Directory -Path (Get-AtdrRuntimeDirectory) -Force | Out-Null
    $kept | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $path -Encoding UTF8
}

function Grant-AtdrTaskToUser {
    # A task registered with administrator rights can otherwise only be read and started with them. The watcher's
    # task has to be started from an ordinary window too: by a release, and by start_system.
    param([string]$TaskName, [string]$UserName)
    $sid = (New-Object System.Security.Principal.NTAccount($UserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $service = New-Object -ComObject Schedule.Service
    $service.Connect()
    $task = $service.GetFolder("\").GetTask($TaskName)
    # 4: the list of who may do what. Read and run for this user, added to what is there.
    $rights = [string]$task.GetSecurityDescriptor(4)
    $ace = "(A;;GRGX;;;$sid)"
    if (-not $rights.Contains($ace)) { $task.SetSecurityDescriptor($rights + $ace, 0) }
}

function Unregister-AtdrTasks {
    $state = Get-AutostartState
    # The watcher's task goes first, or it would start the watcher again within the minute.
    if ($state.watcher) { Unregister-ScheduledTask -TaskName $watchTaskName -Confirm:$false }
    [void](Stop-AtdrWatcherProcess)
    if ($state.desktop) { Unregister-ScheduledTask -TaskName $desktopTaskName -Confirm:$false }
    [void](Stop-AtdrDesktopHelperProcess)
    if ($state.task) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
    if ($state.shortcut) { Remove-Item -LiteralPath $shortcutPath -Force }
}

function Register-AtdrSignInTask {
    param([string]$User)
    $action = New-HiddenPowerShellAction $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $User
    # Windows services ATDR needs (MongoDB) are still starting in the first seconds after sign-in.
    $trigger.Delay = "PT45S"
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Starts ATDR when this user signs in (scripts\start_at_sign_in.ps1). Remove with scripts\autostart.cmd -Remove." -Force -ErrorAction Stop | Out-Null
}

function New-AtdrEveryMinuteTrigger {
    # Every minute, for good. While the task runs a new start is ignored (IgnoreNew), so nothing is launched and
    # no window opens; when it has ended, the next minute starts it again. Windows' own "restart a failed task"
    # does not do this: tried on this laptop, a watcher that was killed stayed down.
    return New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
}

function New-AtdrLongRunningSettings {
    # No time limit: these run for as long as the machine does, or the user is signed in.
    return New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
}

function Start-AtdrWatcherAfresh {
    # Watching from now, not from the trigger's first minute. (Windows needs a moment to see that the watcher
    # which was just ended is gone.)
    for ($waited = 0; $waited -lt 10 -and [string](Get-ScheduledTask -TaskName $watchTaskName).State -eq "Running"; $waited++) { Start-Sleep -Milliseconds 500 }
    [void](Start-AtdrWatcherTask)
}

function Install-AtdrForSignIn {
    param([string]$User)
    $registered = $false
    try {
        Register-AtdrSignInTask $User
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
        $watchPrincipal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName $watchTaskName -Action (New-HiddenPowerShellAction $watchArguments) -Trigger (New-AtdrEveryMinuteTrigger) -Settings (New-AtdrLongRunningSettings) -Principal $watchPrincipal -Description "Keeps ATDR running: restarts a part that stopped (scripts\watch_system.ps1). Remove with scripts\autostart.cmd -Remove." -Force -ErrorAction Stop | Out-Null
        Start-AtdrWatcherAfresh
    }
    catch {
        Write-Host "Windows did not let this user register the watcher task ($($_.Exception.Message.Trim())). ATDR will start at sign-in but will not restart a part that stops." -ForegroundColor Yellow
    }
    # The helper at the desktop belongs to running without a sign-in; here the parts have a desktop themselves.
    if ($null -ne (Get-ScheduledTask -TaskName $desktopTaskName -ErrorAction SilentlyContinue)) { Unregister-ScheduledTask -TaskName $desktopTaskName -Confirm:$false }
    [void](Stop-AtdrDesktopHelperProcess)
    Save-AtdrAutostartRecord @{ mode = "at_sign_in"; user = $User; installed_at = (Get-Date).ToUniversalTime().ToString("o") }
}

function Install-AtdrBeforeSignIn {
    # Runs with administrator rights. What it registers runs without them.
    param([string]$User)
    Register-AtdrSignInTask $User
    if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) { Remove-Item -LiteralPath $shortcutPath -Force }

    [void](Stop-AtdrWatcherProcess)
    # As this user and with no more than this user's ordinary rights, without a stored password (S4U), whether or
    # not the user is signed in. No console window is asked for where there is no desktop to put one on.
    $watchPrincipal = New-ScheduledTaskPrincipal -UserId $User -LogonType S4U -RunLevel Limited
    $withTheMachine = New-ScheduledTaskTrigger -AtStartup
    $watchAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $watchArguments -WorkingDirectory $root
    # With the machine, and every minute: after a shutdown with Windows' fast startup the machine does not start
    # in the sense the first trigger means, and the second one is what brings the watcher up.
    Register-ScheduledTask -TaskName $watchTaskName -Action $watchAction -Trigger @($withTheMachine, (New-AtdrEveryMinuteTrigger)) -Settings (New-AtdrLongRunningSettings) -Principal $watchPrincipal -Description "Keeps ATDR running, whether or not anyone is signed in: starts it with the machine and restarts a part that stopped (scripts\watch_system.ps1). Remove with scripts\autostart.cmd -Remove." -Force -ErrorAction Stop | Out-Null

    $desktopPrincipal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $desktopTaskName -Action (New-HiddenPowerShellAction $desktopArguments) -Trigger @((New-ScheduledTaskTrigger -AtLogOn -User $User), (New-AtdrEveryMinuteTrigger)) -Settings (New-AtdrLongRunningSettings) -Principal $desktopPrincipal -Description "Shows ATDR's Windows notifications to the user who is signed in (scripts\desktop_agent.ps1). Remove with scripts\autostart.cmd -Remove." -Force -ErrorAction Stop | Out-Null

    Save-AtdrAutostartRecord @{ mode = "before_sign_in"; user = $User; installed_at = (Get-Date).ToUniversalTime().ToString("o") }
    # After the record: a task that could not be opened to the user is still registered, and still runs.
    foreach ($name in @($taskName, $watchTaskName, $desktopTaskName)) {
        try { Grant-AtdrTaskToUser -TaskName $name -UserName $User }
        catch { Write-Host "The task '$name' could not be opened to $User ($($_.Exception.Message.Trim())): it can be read and started with administrator rights only." }
    }
    Start-AtdrWatcherAfresh
    Write-Host "Registered: ATDR's watcher starts with the machine and runs without a sign-in, as $User and without administrator rights."
}

function Wait-AtdrWatcherWithoutDesktop {
    # Registered is not yet running. True once this folder's watcher is seen running in the session that has no
    # desktop; until then nothing of ATDR is stopped, because nothing would be there to start it again.
    param([int]$Seconds = 90)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if ((Get-AtdrWatcherSession) -eq 0) { return $true }
        [void](Start-AtdrWatcherTask)
        Start-Sleep -Seconds 3
    }
    return $false
}

function Test-AtdrElevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object System.Security.Principal.WindowsPrincipal($identity)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-AtdrElevated {
    # Runs this script once more with administrator rights, for the part that needs them, and waits for it.
    param([string[]]$Switches, [string]$User)
    $logDir = Join-Path (Get-AtdrRuntimeDirectory) "logs"
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    $logPath = Join-Path $logDir "autostart-install.log"
    Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
    $line = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" $($Switches -join ' ') -Elevated -ForUser `"$User`" -LogTo `"$logPath`""
    Write-Host "This needs administrator rights once. Windows asks now: 'Do you want to allow this app to make changes?' Choose Yes." -ForegroundColor Cyan
    try {
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList $line -Verb RunAs -PassThru -ErrorAction Stop
    }
    catch {
        Write-Host "Administrator rights were not given ($($_.Exception.Message.Trim())). Nothing was changed." -ForegroundColor Yellow
        return $false
    }
    $null = $process.Handle
    if (-not $process.WaitForExit(300000)) {
        Write-Host "The part with administrator rights did not finish in five minutes. Its log: $logPath" -ForegroundColor Yellow
        return $false
    }
    if (Test-Path -LiteralPath $logPath -PathType Leaf) { Get-Content -LiteralPath $logPath | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "  $_" } }
    # How it ended is asked of Windows by the caller (which tasks are there now); this is only a first word.
    try { return ($process.ExitCode -eq 0) } catch { return $true }
}

function Set-AtdrMainsAwake {
    # Every plan the machine has: a laptop's own performance modes switch between them, and a plan that was left
    # out would bring the sleep back with the next switch. What each plan said before is kept, to be put back.
    $before = [ordered]@{}
    foreach ($plan in @(Get-AtdrPowerPlans)) {
        $seconds = Get-AtdrMainsSleepSeconds -Plan $plan
        if ($null -eq $seconds) { continue }
        $before[$plan] = [int]$seconds
        if ($seconds -ne 0) { powercfg /setacvalueindex $plan SUB_SLEEP STANDBYIDLE 0 | Out-Null }
    }
    if (-not $before.Count) {
        # Nothing was read, so nothing was changed, and nothing is on record as wanted.
        Write-Host "Windows did not say after how long this machine goes to sleep on mains power (powercfg /query), so that was left as it is." -ForegroundColor Yellow
        return
    }
    # The plan in use takes a changed value only when it is made the plan in use again.
    powercfg /setactive SCHEME_CURRENT | Out-Null
    $record = Read-AtdrAutostartRecord
    $known = $null -ne $record -and $record.PSObject.Properties["mains_sleep_before"] -and $null -ne $record.mains_sleep_before
    # Not over what an earlier run kept: by now every plan says "never", which is not what was there before.
    if ($known) { Save-AtdrAutostartRecord @{ stay_awake_on_mains = $true } }
    else { Save-AtdrAutostartRecord @{ stay_awake_on_mains = $true; mains_sleep_before = $before } }
    Write-Host "On mains power this machine no longer goes to sleep by itself ($($before.Count) power plans). Closing the lid still puts it to sleep; on battery nothing changed." -ForegroundColor Green
}

function Restore-AtdrMainsSleep {
    $record = Read-AtdrAutostartRecord
    if ($null -eq $record -or -not $record.PSObject.Properties["mains_sleep_before"] -or $null -eq $record.mains_sleep_before) { return }
    foreach ($property in $record.mains_sleep_before.PSObject.Properties) {
        powercfg /setacvalueindex $property.Name SUB_SLEEP STANDBYIDLE ([int]$property.Value) 2>$null | Out-Null
    }
    powercfg /setactive SCHEME_CURRENT | Out-Null
    Save-AtdrAutostartRecord @{ stay_awake_on_mains = $false; mains_sleep_before = $null }
    Write-Host "The time after which this machine goes to sleep on mains power is as it was before."
}

function Restart-AtdrThroughWatcher {
    # Stops ATDR and has the watcher that runs now start it, so that the parts belong to that watcher. True when
    # ATDR is running afterwards. Never leaves it stopped for good: meant to run, it is started at the watcher's
    # next look even when this did not go well.
    $stop = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$(Join-Path $PSScriptRoot 'stop_system.ps1')`"") -WindowStyle Hidden -PassThru
    $null = $stop.Handle
    $stop.WaitForExit()
    if ($stop.ExitCode -ne 0) {
        Write-Host "ATDR could not be stopped (exit code $($stop.ExitCode))." -ForegroundColor Yellow
        Set-AtdrDesiredState -State "running" -By "autostart"
        return $false
    }
    $answer = Request-AtdrStart -By "autostart"
    if ($null -eq $answer) {
        Set-AtdrDesiredState -State "running" -By "autostart"
        Write-Host "The watcher did not answer within eight minutes. Its log: .atdr_runtime\logs\watch.log" -ForegroundColor Yellow
        return $false
    }
    if (-not $answer.ok) {
        Write-Host "ATDR did not start: $($answer.said)" -ForegroundColor Yellow
        return $false
    }
    return $true
}

function Move-AtdrPartsToWatcher {
    # Parts that were started the other way are not where this install wants them. Those of a sign-in session end
    # with it; those without a desktop have nobody to show their notifications once the helper is gone. Stopped
    # and started once through the watcher that runs now, they belong to it. False when they were stopped and
    # that watcher could not start them.
    param([switch]$WithoutDesktop)
    $metadataPath = Join-Path (Get-AtdrRuntimeDirectory) "system-processes.json"
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) { return $true }
    $records = @()
    try { $records = @((Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json).processes) } catch { return $true }
    $elsewhere = @($records | Where-Object { Test-TrackedProcessRecordActive $_ } |
        Where-Object { ((Get-Process -Id ([int]$_.pid)).SessionId -eq 0) -ne [bool]$WithoutDesktop })
    if (-not $elsewhere.Count) { return $true }
    $where = if ($WithoutDesktop) { "still belong to this sign-in session" } else { "were started without a desktop" }
    Write-Host "ATDR's parts $where ($(@($elsewhere | ForEach-Object { [string]$_.name }) -join ', ')). Restarting ATDR once, under its watcher; this takes about two minutes." -ForegroundColor Cyan
    if (-not (Restart-AtdrThroughWatcher)) { return $false }
    Write-Host "ATDR is running again, started by its watcher." -ForegroundColor Green
    return $true
}

function Undo-AtdrBeforeSignIn {
    # Back to starting at sign-in, so that ATDR is looked after as it was before this install. True when it is.
    param([string]$User)
    Write-Host "Going back to starting at sign-in, so that ATDR is looked after as it was. Windows asks for an administrator once more." -ForegroundColor Yellow
    if (Test-AtdrElevated) { Unregister-AtdrTasks } else { [void](Invoke-AtdrElevated -Switches @("-Remove") -User $User) }
    if ((Get-AutostartState).without_sign_in) {
        Write-Host "The watcher's task could not be taken back. Run scripts\autostart.cmd -AtSignIn and choose Yes when Windows asks." -ForegroundColor Yellow
        return $false
    }
    Install-AtdrForSignIn $User
    return $true
}

if ($Status) {
    Write-AutostartState
    exit 0
}

# The entries belong to the folder ATDR runs from. Installed or removed from the folder it is developed in,
# they would start that folder's unfinished work at the next sign-in, or leave the live copy with nobody starting it.
$liveCopy = Get-AtdrLiveCopy
if ($liveCopy) {
    Write-Host "ATDR runs from $liveCopy, not from this folder (the one it is developed in). Run $liveCopy\scripts\autostart.cmd instead." -ForegroundColor Yellow
    exit 1
}

foreach ($needed in @($launcher, $watcher, $desktop)) {
    if (-not (Test-Path -LiteralPath $needed -PathType Leaf)) { throw "scripts\$(Split-Path -Leaf $needed) is missing." }
}
$user = if ($ForUser) { $ForUser } else { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }

if ($Elevated) {
    # The half with administrator rights: the tasks and nothing else. What it says goes to a file, because its
    # window is not the one the person is looking at.
    $code = 0
    $said = New-Object System.Collections.Generic.List[string]
    try {
        & {
            # Either the tasks that run without a sign-in, or the removal of the ones that were registered so.
            # Everything else is done without administrator rights by the run that asked for this one.
            if ($BeforeSignIn) { Install-AtdrBeforeSignIn $user }
            else { Unregister-AtdrTasks; Write-Host "Removed ATDR's start-up entries." }
        } *>&1 | ForEach-Object { $said.Add([string]$_) }
    }
    catch {
        $said.Add("Failed: $($_.Exception.Message)")
        $code = 1
    }
    if ($LogTo) { Set-Content -LiteralPath $LogTo -Value $said -Encoding UTF8 }
    exit $code
}

# Tasks that run without a sign-in were registered with administrator rights, and can only be changed with them.
if ($BeforeSignIn -and $AtSignIn) { throw "Give -BeforeSignIn or -AtSignIn, not both." }
$already = Read-AtdrAutostartRecord
$installedBefore = ($null -ne $already -and [string]$already.mode -eq "before_sign_in")
$withAdministrator = $BeforeSignIn -or $installedBefore
$asAdministrator = Test-AtdrElevated
# The way that is installed stays unless another one is asked for.
$wantBefore = $BeforeSignIn -or ($installedBefore -and -not $AtSignIn)
# Only the sleep time: the entries are there and no other way of starting was asked for.
$onlyPower = $StayAwakeOnMains -and -not $BeforeSignIn -and -not $AtSignIn -and -not $Remove -and $null -ne $already

if ($Remove) {
    Restore-AtdrMainsSleep
    if ($withAdministrator -and -not $asAdministrator) {
        [void](Invoke-AtdrElevated -Switches @("-Remove") -User $user)
        if ((Get-AutostartState).watcher) {
            Write-Host "ATDR's start-up entries are still there: removing them needs administrator rights." -ForegroundColor Yellow
            exit 1
        }
    }
    else {
        Unregister-AtdrTasks
    }
    Remove-Item -LiteralPath (Get-AtdrAutostartRecordPath) -Force -ErrorAction SilentlyContinue
    Write-AutostartState
    exit 0
}

if ($onlyPower) {
    Set-AtdrMainsAwake
    Write-AutostartState
    exit 0
}

if ($wantBefore) {
    if ($asAdministrator) { Install-AtdrBeforeSignIn $user }
    else { [void](Invoke-AtdrElevated -Switches @("-BeforeSignIn") -User $user) }
    # Looked at, not taken on trust: what counts is what this folder has on record, and the watcher that runs.
    if (-not (Test-AtdrRunsWithoutSignIn)) {
        Write-Host "ATDR was not registered to start with the machine. Nothing else was changed." -ForegroundColor Yellow
        exit 1
    }
    if (-not (Wait-AtdrWatcherWithoutDesktop)) {
        $result = try { "0x{0:X8}" -f [uint32]([int64](Get-ScheduledTaskInfo -TaskName $watchTaskName -ErrorAction Stop).LastTaskResult -band 0xFFFFFFFFL) } catch { "not readable from this window" }
        Write-Host "Windows registered the watcher to run without a sign-in but did not start it that way (its last result: $result). ATDR's parts were left running as they are." -ForegroundColor Yellow
        # Without this ATDR would have no watcher at all: the one of the sign-in session was ended by the install.
        [void](Undo-AtdrBeforeSignIn $user)
        Write-AutostartState
        exit 1
    }
    # The helper at the desktop is started for this sign-in now; from the next one on, the sign-in starts it.
    try {
        $helper = Get-ScheduledTask -TaskName $desktopTaskName -ErrorAction Stop
        if ([string]$helper.State -ne "Running") { Start-ScheduledTask -TaskName $desktopTaskName -ErrorAction Stop }
    }
    catch {
        Write-Host "The task '$desktopTaskName' could not be started from here ($($_.Exception.Message.Trim())); Windows starts it within a minute." -ForegroundColor Yellow
    }
    if (-not (Move-AtdrPartsToWatcher -WithoutDesktop)) {
        # ATDR does not come up where there is no desktop, and is down now. It ran before the install: back to that.
        Write-Host "ATDR did not start under the watcher that runs without a sign-in. Why is in .atdr_runtime\logs\watch.log and in each part's own log." -ForegroundColor Yellow
        if (Undo-AtdrBeforeSignIn $user) {
            Write-Host "Starting ATDR as it ran before, in this sign-in session; this takes about two minutes." -ForegroundColor Cyan
            if (Restart-AtdrThroughWatcher) { Write-Host "ATDR is running again, as it ran before the install." -ForegroundColor Green }
            else { Write-Host "ATDR is not running. Run scripts\start_system.cmd to see why." -ForegroundColor Red }
        }
        Write-AutostartState
        exit 1
    }
}
else {
    if ($withAdministrator) {
        # Back to starting at sign-in: the entries that run without one go first, which takes an administrator.
        if ($asAdministrator) { Unregister-AtdrTasks } else { [void](Invoke-AtdrElevated -Switches @("-Remove") -User $user) }
        if ((Get-AutostartState).without_sign_in) {
            Write-Host "ATDR still starts with the machine: changing that needs administrator rights. Nothing else was changed." -ForegroundColor Yellow
            exit 1
        }
    }
    Install-AtdrForSignIn $user
    # Parts a watcher without a desktop had started have no helper to show their notifications any more.
    if (-not (Move-AtdrPartsToWatcher)) {
        Write-Host "ATDR is not running. Run scripts\start_system.cmd to see why; the watcher goes on trying every few minutes." -ForegroundColor Yellow
    }
}

if ($StayAwakeOnMains) { Set-AtdrMainsAwake }
Write-AutostartState
