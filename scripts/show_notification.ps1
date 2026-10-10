# Shows one Windows notification from ATDR on this machine.
# The words come in environment variables (ATDR_NOTIFICATION_TITLE, _BODY, _LINK), so nothing has to be quoted.
# Clicking the notification opens the link in the browser. Exit code 2: no title was given.
$ErrorActionPreference = "Stop"

$title = [string]$env:ATDR_NOTIFICATION_TITLE
$body = [string]$env:ATDR_NOTIFICATION_BODY
$link = [string]$env:ATDR_NOTIFICATION_LINK
if (-not $title.Trim()) { exit 2 }

# Windows names a notification's sender by this entry; without it the sender reads "Windows PowerShell".
$appId = "MFU.ATDR"
$appKey = "HKCU:\Software\Classes\AppUserModelId\$appId"
if (-not (Test-Path -LiteralPath $appKey)) { [void](New-Item -Path $appKey -Force) }
if ((Get-ItemProperty -LiteralPath $appKey -Name DisplayName -ErrorAction SilentlyContinue).DisplayName -ne "MFU ATDR") {
    Set-ItemProperty -LiteralPath $appKey -Name DisplayName -Value "MFU ATDR"
}

[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]

function ConvertTo-XmlText([string]$Text) { [System.Security.SecurityElement]::Escape($Text) }

$launch = ""
# Only a web address is opened: the link is handed to Windows as it is.
if ($link -match '^https?://') { $launch = " activationType=`"protocol`" launch=`"$(ConvertTo-XmlText $link)`"" }
$texts = "<text>$(ConvertTo-XmlText $title)</text>"
if ($body.Trim()) { $texts += "<text>$(ConvertTo-XmlText $body)</text>" }
$document = New-Object Windows.Data.Xml.Dom.XmlDocument
$document.LoadXml("<toast$launch><visual><binding template=`"ToastGeneric`">$texts</binding></visual></toast>")
$toast = New-Object Windows.UI.Notifications.ToastNotification $document
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
exit 0
