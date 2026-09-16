@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap_advisory_anomaly.ps1" %*
exit /b %ERRORLEVEL%
