@echo off
rem Puts a checked version of ATDR live. Run in the folder ATDR is developed in:
rem   scripts\release.cmd            what runs, and what is waiting
rem   scripts\release.cmd go         check HEAD and make it the version that runs
rem   scripts\release.cmd back       the version before
rem   scripts\release.cmd recover    after a release that was cut off
rem   scripts\release.cmd setup      once: make the live copy
pushd "%~dp0.."
".venv\Scripts\python.exe" -m atdr.scripts.release %*
set "ATDR_RELEASE_EXIT=%ERRORLEVEL%"
popd
exit /b %ATDR_RELEASE_EXIT%
