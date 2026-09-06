@echo off
powershell.exe -NoLogo -NoProfile -File "%~dp0Manage-LD14-Guard.ps1" -Action Start
if errorlevel 1 pause
