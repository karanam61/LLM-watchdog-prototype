@echo off
set ROOT=%~dp0..\..
for %%I in ("%ROOT%") do set ROOT=%%~fI

cd /d "%ROOT%"
echo Starting Backend with py... > "%ROOT%\backend_status.log"
py app.py >> "%ROOT%\backend_status.log" 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo py failed, trying python... >> "%ROOT%\backend_status.log"
    python app.py >> "%ROOT%\backend_status.log" 2>&1
)
