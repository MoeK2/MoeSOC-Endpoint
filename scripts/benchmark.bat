@echo off
rem Pipeline benchmark on synthetic events (real timings on this PC). See docs/benchmarks.md.
rem Uses a throwaway database in %TEMP%; your MoeSOC data and Windows logs are not touched.
rem Output: benchmark_output.txt and docs\benchmarks\windows-pc.json
cd /d "%~dp0.."
set PYTHONUTF8=1
set "OUT=%CD%\benchmark_output.txt"
echo MoeSOC benchmark - %DATE% %TIME% > "%OUT%"
".venv\Scripts\python.exe" scripts\benchmark.py --json docs\benchmarks\windows-pc.json >> "%OUT%" 2>&1
echo exit code %ERRORLEVEL% >> "%OUT%"
