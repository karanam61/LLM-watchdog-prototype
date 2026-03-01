@echo off
echo ============================================
echo   AI-SOC WATCHDOG - STOPPING ALL SERVICES
echo ============================================
echo.
taskkill /F /IM python.exe 2>nul && echo [OK] Python (backend) stopped || echo [--] Python not running
taskkill /F /IM node.exe 2>nul && echo [OK] Node (frontend) stopped || echo [--] Node not running
echo.
echo All services stopped.
pause
