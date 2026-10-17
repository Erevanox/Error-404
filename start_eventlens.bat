@echo off
title TraceX - Cybersecurity Incident Correlation System
echo =========================================================================
echo    TraceX - Cybersecurity Incident Correlation ^& Visualization System
echo    "Evidence First. Human Guided. Defensive by Design."
echo =========================================================================
echo.

echo [1/2] Starting Python FastAPI Backend on http://127.0.0.1:8001 ...
cd /d "%~dp0backend"
start "TraceX-Backend" cmd /k "python -m uvicorn main:app --host 127.0.0.1 --port 8001"

timeout /t 3 /nobreak >nul

echo [2/2] Starting React Frontend on http://localhost:5174 ...
cd /d "%~dp0frontend"
start "TraceX-Frontend" cmd /k "npm.cmd run dev -- --host 127.0.0.1 --port 5174"

timeout /t 4 /nobreak >nul

echo.
echo =========================================================================
echo  TraceX is running!
echo  Frontend UI: http://localhost:5174/
echo  Backend API: http://127.0.0.1:8001/api/health
echo  Swagger Docs: http://127.0.0.1:8001/docs
echo =========================================================================
start "" "http://localhost:5174/"
exit
