@echo off
REM Double-click to launch the local test target, or run: serve.bat [port]
cd /d "%~dp0"
where py >nul 2>nul && (py serve.py %* & goto :eof)
where python >nul 2>nul && (python serve.py %* & goto :eof)
echo Python 3 was not found on PATH. Install it from https://python.org and retry.
pause
