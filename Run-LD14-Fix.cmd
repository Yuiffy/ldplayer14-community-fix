@echo off
setlocal
where py.exe >nul 2>nul
if errorlevel 1 goto missing
py -3 -c "import ctypes,sys; sys.exit(0 if sys.version_info >= (3,10) and ctypes.sizeof(ctypes.c_void_p) == 8 else 1)" >nul 2>nul
if errorlevel 1 goto missing
py -3 "%~dp0ld14-local-fix.py" %*
exit /b %errorlevel%
:missing
echo This package requires 64-bit Python 3.10 or newer and the Python Launcher.
echo Install from https://www.python.org/downloads/windows/ and include py.exe.
echo See the included installation guide for setup and manual Python commands.
exit /b 1
