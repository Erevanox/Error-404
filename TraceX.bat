@echo off
title TraceX Launcher
cd /d "%~dp0backend"
start "TraceX Backend" cmd /k "python -m uvicorn main:app --host 127.0.0.1 --port 8001"
timeout /t 3 /nobreak >nul
cd /d "%~dp0frontend"
start "TraceX Frontend" cmd /k "npm.cmd run dev -- --host 127.0.0.1 --port 5174"
timeout /t 5 /nobreak >nul
start "" "http://localhost:5174/"
exit
