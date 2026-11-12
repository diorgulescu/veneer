@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0verify-e2e.ps1" %*
exit /b %ERRORLEVEL%
