@echo off
rem Portfolio demo with SYNTHETIC data in a separate database (see docs\demo.md).
rem   scripts\demo.bat               open MoeSOC in demo mode
rem   scripts\demo.bat screenshots   save the demo screenshots to docs\screenshots\demo and exit
cd /d "%~dp0.."
set PYTHONUTF8=1
if /I "%~1"=="screenshots" (
  ".venv\Scripts\python.exe" scripts\demo.py --screenshots docs\screenshots\demo > demo_output.txt 2>&1
  echo exit code %ERRORLEVEL% >> demo_output.txt
) else (
  start "" ".venv\Scripts\pythonw.exe" scripts\demo.py
)
