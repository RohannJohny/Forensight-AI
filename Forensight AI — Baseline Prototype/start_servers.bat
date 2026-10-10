@echo off
title Forensight AI Launcher
echo ============================================================
echo   Forensight AI - Launching Platform Services
echo ============================================================
echo.

echo [*] Starting Backend API (FastAPI on http://localhost:8000)...
start "Forensight Backend API" cmd /k "cd /d %~dp0backend && python -m uvicorn app.main:app --reload --port 8000"

echo [*] Starting Frontend UI (Vite on http://localhost:5173)...
start "Forensight Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo [*] Waiting for services to initialize...
timeout /t 3 /nobreak >nul

echo [*] Opening browser to http://localhost:5173 ...
start http://localhost:5173

echo.
echo ============================================================
echo   Forensight AI is now running!
echo   - Web Dashboard: http://localhost:5173
echo   - Backend Docs:  http://localhost:8000/docs
echo ============================================================
