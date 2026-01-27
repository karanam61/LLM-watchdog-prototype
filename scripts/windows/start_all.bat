@echo off
set ROOT=%~dp0..\..
for %%I in ("%ROOT%") do set ROOT=%%~fI

echo ===================================================
echo   AI-SOC WATCHDOG - STARTUP SCRIPT
echo ===================================================

echo [1/2] Starting Backend Server (Port 5000)...
start "AI-SOC BACKEND" cmd /k "cd /d "%ROOT%" && py app.py"

echo Waiting 3 seconds...
timeout /t 3 /nobreak >nul

echo [2/2] Starting Frontend Dashboard (Port 5173)...
start "AI-SOC FRONTEND" cmd /k "cd /d "%ROOT%\soc-dashboard" && npm run dev"

echo.
echo ===================================================
echo   SYSTEMS LAUNCHED
echo ===================================================
echo   1. Backend: http://localhost:5000
echo   2. Frontend: http://localhost:5173
echo.
echo   Keep these black windows OPEN. Closing them kills the server.
echo.
pause
