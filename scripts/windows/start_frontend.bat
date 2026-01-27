@echo off
set ROOT=%~dp0..\..
for %%I in ("%ROOT%") do set ROOT=%%~fI

cd /d "%ROOT%\soc-dashboard"
echo Starting Frontend... > "%ROOT%\soc-dashboard\frontend_status.log"
call npm run dev >> "%ROOT%\soc-dashboard\frontend_status.log" 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Frontend failed with error %ERRORLEVEL% >> "%ROOT%\soc-dashboard\frontend_status.log"
)
