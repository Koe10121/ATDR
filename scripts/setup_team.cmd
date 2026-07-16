@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_team.ps1" %*
exit /b %ERRORLEVEL%
