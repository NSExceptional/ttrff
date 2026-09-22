@echo off
rem tt-mod-stop.cmd -- Windows twin of scripts/tt-mod-stop: cleanly STOP the resident TTR mod
rem injector (frida/trampoline_inject.py) so it REVERTS every installed wrap BEFORE the frida
rem session drops. THIS IS THE RELIABLE STOP. Ctrl+C is not: killing the injector mid-hook leaves
rem the MetaInterval.start trampoline installed while the agent's memory is freed, which crashes
rem the game on the next animation. This script drops the STOP FILE the injector's resident poll
rem loop watches; the injector then reverts ALL wraps, detaches cleanly, removes the file, exits.
rem
rem   tt-mod-stop.cmd                       drop the stop file, wait for a clean revert + exit
rem   TTRMOD_STOPFILE=X:\path tt-mod-stop    non-default stop-file path (must match the injector env)
rem
rem Exit 0 = injector reverted + exited (or was not running). Exit 1 = timed out (the injector may
rem be STAYING ATTACHED because it could not confirm the revert -- that is the SAFE state, game
rem alive -- retry when the game is responsive).
rem
rem The stop file default on Windows is %TEMP%\ttrmod-stop -- the SAME file the tray app watches
rem (TTRFF_STOPFILE / TTRMOD_STOPFILE both honored), so this script and the tray agree.

setlocal EnableExtensions

if defined TTRMOD_STOPFILE (
    set "STOPFILE=%TTRMOD_STOPFILE%"
) else (
    set "STOPFILE=%TEMP%\ttrmod-stop"
)

set "TIMEOUT_TICKS=120"
set "TICK=5"

echo [tt-mod-stop] requesting graceful stop via %STOPFILE%
echo [tt-mod-stop] (this is the SAFE way to stop -- killing the injector can crash the game)
type nul > "%STOPFILE%"

rem Wait until no python host is running trampoline_inject.py (up to TIMEOUT_TICKS * TICK secs).
rem Detection via PowerShell Get-CimInstance (wmic is removed on Windows 11 24H2+); the Windows
rem injector runs as the SAME user (no sudo), so a plain same-user process query sees it.
set /a "WAITED=0"
:waitloop
set "RUNNING="
for /f "usebackq delims=" %%p in (`powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter \"Name='python.exe' or Name='pythonw.exe'\" | Where-Object { $_.CommandLine -like '*trampoline_inject.py*' }).Count" 2^>nul`) do (
    if %%p GTR 0 if not defined RUNNING set "RUNNING=1"
)
if not defined RUNNING goto done
set /a "WAITED+=TICK"
if %WAITED% GEQ %TIMEOUT_TICKS% goto timeout
timeout /t %TICK% /nobreak >nul
goto waitloop

:timeout
echo [tt-mod-stop] timed out after %TIMEOUT_TICKS% ticks -- the injector may be staying attached
echo [tt-mod-stop] because it could not confirm the revert (SAFE state: game alive). Retry when
echo [tt-mod-stop] the game is responsive, or quit the tray app (it waits out the revert itself).
exit /b 1

:done
echo [tt-mod-stop] injector reverted and exited cleanly.
if exist "%STOPFILE%" del /q "%STOPFILE%" >nul 2>&1
endlocal & exit /b 0
