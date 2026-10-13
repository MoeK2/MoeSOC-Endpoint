@echo off
rem Read-only Event Log API check (see scripts\check_eventlog_api.py). Output: eventlog_api_output.txt
cd /d "%~dp0.."
set PYTHONUTF8=1
".venv\Scripts\python.exe" scripts\check_eventlog_api.py > eventlog_api_output.txt 2>&1
echo exit code %ERRORLEVEL% >> eventlog_api_output.txt
