@echo off
rem Real check that Live monitoring delivers new Security events (audit item A-4).
rem Windows shows the standard UAC prompt; nothing runs elevated unless you approve it.
rem Uses a separate live-validation-data folder; your MoeSOC data is not touched.
rem Output: live_delivery_output.txt
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0.."
set PYTHONUTF8=1
".venv\Scripts\python.exe" scripts\validate_live_delivery.py > live_delivery_console.txt 2>&1
