@echo off
rem ttrff.cmd -- Scoop/portable launcher for the ttrff tray app (Windows).
rem
rem Runs tray/ttrff_tray.py under a PRIVATE venv (created on first run inside this
rem install dir) that carries the tray deps (pystray, pillow, psutil, frida). This
rem mirrors what the Homebrew formula does (pinned prebuilt wheels into a private
rem venv) and keeps the install self-contained: no global pip installs, no PATH
rem pollution, `scoop uninstall ttrff` removes everything.
rem
rem The venv is created from the `python` on PATH (Scoop's python, if installed via
rem Scoop, or any python 3.8+). If python is missing, print an actionable error.
rem
rem --hidden: run under pythonw (no console window) -- used by the Startup shortcut
rem so logging in doesn't flash a terminal. The tray writes its own log either way.
setlocal EnableExtensions
set "APPDIR=%~dp0.."
set "VENV=%APPDIR%\venv"
set "PY=%VENV%\Scripts\python.exe"

where python >nul 2>nul
if errorlevel 1 (
    echo [ttrff] python not found on PATH -- install it first, e.g.:
    echo        scoop install python
    exit /b 1
)

if not exist "%PY%" (
    echo [ttrff] first run: creating private venv + installing deps ^(pystray pillow psutil frida^)...
    python -m venv "%VENV%" || goto :fail
    "%PY%" -m pip install --disable-pip-version-check --quiet pystray pillow psutil frida || goto :fail
)

rem TTRFF_REPO points the tray at the bundled toolset (frida/, modset.json, RE tables).
rem The editable mod table is seeded to %LOCALAPPDATA%\ttrff\modset.json on first run
rem (TTRMOD_MODSET), so `scoop update` / reinstall never clobbers the user's factors.
if "%TTRMOD_MODSET%"=="" set "TTRMOD_MODSET=%LOCALAPPDATA%\ttrff\modset.json"
set "TTRFF_REPO=%APPDIR%"

if "%1"=="--hidden" (
    rem startup-item mode: pythonw detaches from the console; the tray keeps running
    start "" /b "%VENV%\Scripts\pythonw.exe" "%APPDIR%\tray\ttrff_tray.py" %*
    exit /b 0
)

"%PY%" "%APPDIR%\tray\ttrff_tray.py" %*
exit /b %ERRORLEVEL%

:fail
echo [ttrff] venv setup failed -- see the messages above.
exit /b 1
