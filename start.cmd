@echo off
rem start.cmd - netryx_demo launcher (thin shell): switch to UTF-8 then delegate to start.ps1.
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
exit /b %errorlevel%
