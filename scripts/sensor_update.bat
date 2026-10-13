@echo off
rem Updates an installed MoeSOC Sensor from a fresh build (dist\MoeSOC), UAC prompt.
rem Stops the service, copies the build to Program Files, updates the registration,
rem starts it and records the status. Data is kept. Output: sensor_update_output.txt
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0.."
set "OUT=%CD%\sensor_update_output.txt"
set "SENSOR=%ProgramFiles%\MoeSOC Endpoint\MoeSOCSensor.exe"
echo MoeSOC sensor update - %DATE% %TIME% > "%OUT%"
"dist\MoeSOC\MoeSOCSensor.exe" install --copy-to-program-files >> "%OUT%" 2>&1
echo exit code %ERRORLEVEL% >> "%OUT%"
timeout /t 20 /nobreak >nul
"%SENSOR%" status >> "%OUT%" 2>&1
"%SENSOR%" restart >> "%OUT%" 2>&1
timeout /t 15 /nobreak >nul
"%SENSOR%" status >> "%OUT%" 2>&1
powershell -NoProfile -Command "Get-Content -Tail 30 \"$env:ProgramData\MoeSOC\logs\sensor.log\"" >> "%OUT%" 2>&1
echo ===== DONE >> "%OUT%"
