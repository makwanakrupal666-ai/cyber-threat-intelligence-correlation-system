@echo off
setlocal

title CTI CORE - Launcher

set "PROJECT=D:\Projects\cti-project"
set "BACKEND=%PROJECT%\.venv\Scripts\python.exe"
set "FRONTEND=%PROJECT%\frontend"

echo.
echo ==========================================
echo          CTI CORE - STARTING
echo ==========================================
echo.

if not exist "%BACKEND%" (
    echo [ERROR] Python virtual environment not found:
    echo %BACKEND%
    pause
    exit /b 1
)

if not exist "%FRONTEND%\package.json" (
    echo [ERROR] Frontend not found:
    echo %FRONTEND%
    pause
    exit /b 1
)

echo [1/3] Starting FastAPI backend...
start "CTI CORE - Backend" powershell -NoExit -ExecutionPolicy Bypass -Command "Set-Location '%PROJECT%'; & '%BACKEND%' -m uvicorn backend.main:app --host 127.0.0.1 --port 8000"

timeout /t 3 /nobreak >nul

echo [2/3] Starting React frontend...
start "CTI CORE - Frontend" powershell -NoExit -ExecutionPolicy Bypass -Command "Set-Location '%FRONTEND%'; npm run dev -- --host 127.0.0.1"

timeout /t 5 /nobreak >nul

echo [3/3] Opening CTI CORE dashboard...
start "" "http://localhost:5173/"

echo.
echo ==========================================
echo CTI CORE is starting.
echo Dashboard: http://localhost:5173/
echo Backend:   http://127.0.0.1:8000/
echo ==========================================
echo.
echo You can minimize this launcher window.
echo Keep the Backend and Frontend windows open while using CTI CORE.
echo.
pause
