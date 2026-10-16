@echo off
title EventLens - Cybersecurity Incident Correlation System
echo =========================================================================
echo    EventLens - Cybersecurity Incident Correlation & Visualization System
echo    "Evidence First. Human Guided. Defensive by Design."
echo =========================================================================
echo.

set PATH=C:\antigravity\node;%USERPROFILE%\.local\bin;%PATH%

echo [1/2] Starting Python FastAPI Backend on http://127.0.0.1:8000 ...
start "EventLens-Backend" cmd /k "cd /d c:\antigravity\trace x\backend && uv run uvicorn main:app --host 127.0.0.1 --port 8000"

timeout /t 2 >nul

echo [2/2] Starting React Frontend on http://localhost:5173 ...
start "EventLens-Frontend" cmd /k "cd /d c:\antigravity\trace x\frontend && node .\node_modules\vite\bin\vite.js --port 5173"

echo.
echo =========================================================================
echo  EventLens is running!
echo  Frontend UI: http://localhost:5173/
echo  Backend API: http://127.0.0.1:8000/api/health
echo  Swagger Docs: http://127.0.0.1:8000/docs
echo =========================================================================
pause
