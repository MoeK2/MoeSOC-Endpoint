@echo off
rem Runs a real, read-only Security log scan with administrator rights.
rem Windows shows a standard UAC prompt; nothing runs elevated unless you approve it.
rem Uses the separate .verify-data folder. Output: elevated_scan_output.txt
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0.."
set PYTHONUTF8=1
set "OUT=%CD%\elevated_scan_output.txt"
set "VPY=%CD%\.venv\Scripts\python.exe"
echo MoeSOC elevated scan - %DATE% %TIME% > "%OUT%"
echo ===== CLI health >> "%OUT%"
"%VPY%" -m moesoc.cli --data-dir .verify-data health >> "%OUT%" 2>&1
echo ===== CLI scan (real Security log, last 24 h) >> "%OUT%"
"%VPY%" -m moesoc.cli --data-dir .verify-data scan >> "%OUT%" 2>&1
echo exit code %ERRORLEVEL% >> "%OUT%"
echo ===== CLI rescan (duplicate check) >> "%OUT%"
"%VPY%" -m moesoc.cli --data-dir .verify-data scan >> "%OUT%" 2>&1
echo ===== CLI events >> "%OUT%"
"%VPY%" -m moesoc.cli --data-dir .verify-data events --limit 12 >> "%OUT%" 2>&1
echo ===== CLI detections >> "%OUT%"
"%VPY%" -m moesoc.cli --data-dir .verify-data detections >> "%OUT%" 2>&1
echo ===== Windows integration tests >> "%OUT%"
"%VPY%" -m pytest -m windows -v -rs -p no:cacheprovider --basetemp "%CD%\.pytest-tmp" >> "%OUT%" 2>&1
echo ===== GUI smoke test (elevated) >> "%OUT%"
"%VPY%" scripts\gui_smoke.py >> "%OUT%" 2>&1
echo ===== DONE >> "%OUT%"
