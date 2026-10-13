@echo off
rem Measures the tray (2 min) and, if open, the console (1 min) - not elevated.
rem Output: appended to sensor_benchmark_output.txt
cd /d "%~dp0.."
set PYTHONUTF8=1
set "VPY=%CD%\.venv\Scripts\python.exe"
"%VPY%" scripts\sensor_benchmark.py watch --name MoeSOCTray.exe --minutes 2
"%VPY%" scripts\sensor_benchmark.py watch --name MoeSOC.exe --minutes 1
"%VPY%" scripts\sensor_benchmark.py burst --events 1000
powershell -NoProfile -Command "(Get-ChildItem -Recurse 'dist\MoeSOC' | Measure-Object -Sum Length).Sum / 1MB" >> sensor_benchmark_output.txt
