@echo off
title TraceX Launcher
rem ---------------------------------------------------------------------------
rem Legacy alias kept for compatibility.
rem
rem This file used to hard-code the original author's machine paths
rem (c:\antigravity\trace x), the "uv" runner and ports 8000/5173, which did not
rem match frontend/vite.config.js (proxy target 127.0.0.1:8001). It now simply
rem calls the current, path-independent launcher that sits next to it.
rem ---------------------------------------------------------------------------
call "%~dp0TraceX.bat"
