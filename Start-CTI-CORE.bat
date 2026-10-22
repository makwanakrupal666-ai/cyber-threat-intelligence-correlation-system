@echo off
setlocal EnableExtensions

rem CTI CORE one-click launcher
rem Keep the backend and frontend console windows open while using the dashboard.
set "PROJECT_DIR=%~dp0"
set "BACKEND_PY=%PROJECT_DIR%.venv\Scripts\python.exe"
set "FRONTEND_DIR=%PROJECT_DIR%frontend"

if not exist "%PROJECT_DIR%backend\main.py" (
    echo ERROR: backend\main.py was not found.
    echo Put this launcher in the project root: D:\Project\cti-project-final
    pause
    exit /b 1
)

if not exist "%BACKEND_PY%" (
    echo ERROR: Python virtual environment was not found at:
    echo %BACKEND_PY%
    echo Check that this launcher is inside the existing project root.
    pause
    exit /b 1
)

if not exist "%FRONTEND_DIR%\package.json" (
    echo ERROR: frontend\package.json was not found.
    pause
    exit /b 1
)

if not exist "%FRONTEND_DIR%\node_modules" (
    echo WARNING: frontend\node_modules is missing.
    echo The frontend may require npm ci from the frontend folder first.
)

echo.
echo ==========================================
echo           CTI CORE Launcher
echo ==========================================
echo.

rem Check whether the backend health endpoint is already responding.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { $r = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/health' -TimeoutSec 2; if ($r.status -eq 'ok') { exit 0 }; exit 1 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo Starting backend on http://127.0.0.1:8000 ...
    start "CTI CORE Backend" /D "%PROJECT_DIR%" cmd.exe /k ".venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000"
) else (
    echo Backend is already running. Skipping duplicate startup.
)

rem Check whether the Vite frontend port is already responding.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:5173' -TimeoutSec 2 -UseBasicParsing; if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500) { exit 0 }; exit 1 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo Starting frontend from the frontend folder ...
    start "CTI CORE Frontend" /D "%FRONTEND_DIR%" cmd.exe /k "npm run dev"
) else (
    echo Frontend port 5173 is already responding. Skipping duplicate startup.
)

echo.
echo Waiting briefly for the dashboard to initialize...
timeout /t 5 /nobreak >nul
start "" "http://localhost:5173"
echo.
echo Dashboard: http://localhost:5173
echo Backend health: http://127.0.0.1:8000/health
echo.
echo Keep the Backend and Frontend console windows open while using CTI CORE.
echo Close those two console windows when you finish.
echo.
timeout /t 4 >nul
exit /b 0
