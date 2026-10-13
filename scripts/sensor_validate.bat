@echo off
rem Always-on sensor: real Windows service validation (explicit install, UAC prompt).
rem   1. installs the PACKAGED build (dist\MoeSOC) into Program Files, registers the
rem      MoeSOCSensor service (virtual account NT SERVICE\MoeSOCSensor, Event Log Readers)
rem   2. status, stop, start, restart, status
rem   3. measures the IDLE sensor for 10 minutes
rem The service keeps running afterwards (that is the point). Remove it with
rem scripts\sensor_uninstall.bat. MoeSOC data is never deleted.
rem Output: sensor_validation_output.txt
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0.."
set PYTHONUTF8=1
set "OUT=%CD%\sensor_validation_output.txt"
set "VPY=%CD%\.venv\Scripts\python.exe"
set "SENSOR=%ProgramFiles%\MoeSOC Endpoint\MoeSOCSensor.exe"
echo MoeSOC sensor validation - %DATE% %TIME% > "%OUT%"
if not exist "dist\MoeSOC\MoeSOCSensor.exe" (
  echo dist\MoeSOC\MoeSOCSensor.exe missing: run scripts\build_installer.bat first >> "%OUT%"
  exit /b 1
)
echo ===== install >> "%OUT%"
"dist\MoeSOC\MoeSOCSensor.exe" install --copy-to-program-files --no-start >> "%OUT%" 2>&1
echo exit code %ERRORLEVEL% >> "%OUT%"
echo ===== start >> "%OUT%"
"%SENSOR%" start >> "%OUT%" 2>&1
timeout /t 20 /nobreak >nul
echo ===== status after start >> "%OUT%"
"%SENSOR%" status >> "%OUT%" 2>&1
echo ===== stop >> "%OUT%"
"%SENSOR%" stop >> "%OUT%" 2>&1
echo ===== start >> "%OUT%"
"%SENSOR%" start >> "%OUT%" 2>&1
echo ===== restart >> "%OUT%"
"%SENSOR%" restart >> "%OUT%" 2>&1
timeout /t 30 /nobreak >nul
echo ===== status after restart >> "%OUT%"
"%SENSOR%" status >> "%OUT%" 2>&1
echo ===== service configuration >> "%OUT%"
sc.exe qc MoeSOCSensor >> "%OUT%" 2>&1
sc.exe qprivs MoeSOCSensor >> "%OUT%" 2>&1
sc.exe qfailure MoeSOCSensor >> "%OUT%" 2>&1
icacls "%ProgramData%\MoeSOC" >> "%OUT%" 2>&1
echo ===== idle benchmark (10 minutes, nothing else should be done meanwhile) >> "%OUT%"
"%VPY%" scripts\sensor_benchmark.py watch --service MoeSOCSensor --minutes 10 >> "%OUT%" 2>&1
echo ===== status after idle >> "%OUT%"
"%SENSOR%" status >> "%OUT%" 2>&1
echo ===== sensor.log tail >> "%OUT%"
powershell -NoProfile -Command "Get-Content -Tail 40 \"$env:ProgramData\MoeSOC\logs\sensor.log\"" >> "%OUT%" 2>&1
echo ===== DONE >> "%OUT%"
