@echo off
rem Stops and removes the MoeSOCSensor service registration (UAC prompt).
rem MoeSOC data in %ProgramData%\MoeSOC is NOT deleted. Output: sensor_uninstall_output.txt
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0.."
set "OUT=%CD%\sensor_uninstall_output.txt"
set "SENSOR=%ProgramFiles%\MoeSOC Endpoint\MoeSOCSensor.exe"
if not exist "%SENSOR%" set "SENSOR=dist\MoeSOC\MoeSOCSensor.exe"
"%SENSOR%" uninstall > "%OUT%" 2>&1
