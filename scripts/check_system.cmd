@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0check_system.ps1" %*
exit /b %ERRORLEVEL%
