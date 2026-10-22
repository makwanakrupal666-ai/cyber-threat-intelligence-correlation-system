@echo off
REM Run this once: python -m venv .venv
REM Then: .venv\Scripts\activate
REM Then: pip install -r requirements.txt
REM This script just starts the API server.

.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
pause
