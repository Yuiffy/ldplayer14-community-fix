@echo off
powershell.exe -NoLogo -NoProfile -File "%~dp0Manage-LD14-Guard.ps1" -Action Status
pause
