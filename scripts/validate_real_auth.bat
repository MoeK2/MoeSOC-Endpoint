@echo off
rem Real-event validation for DET-001 / COR-001 (see docs/validation.md).
rem Read-only: scans the Security log, lists findings, re-verifies evidence by EventRecordID.
rem It never changes audit policy, accounts or any Windows setting.
rem Uses the separate .verify-data folder. Output: validation_output.txt
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0.."
set PYTHONUTF8=1
set "OUT=%CD%\validation_output.txt"
set "VPY=%CD%\.venv\Scripts\python.exe"
set "CLI="%VPY%" -m moesoc.cli --data-dir .verify-data"
echo MoeSOC real-event validation - %DATE% %TIME% > "%OUT%"
echo ===== Logon audit policy (read-only; Logon subcategory GUID is language-independent) >> "%OUT%"
auditpol /get /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} >> "%OUT%" 2>&1
echo ===== Account lockout policy (read-only) >> "%OUT%"
net accounts >> "%OUT%" 2>&1
echo ===== Scan >> "%OUT%"
%CLI% scan >> "%OUT%" 2>&1
echo ===== Recent failed logons (4625) >> "%OUT%"
%CLI% events --event-id 4625 --since-hours 2 --limit 15 >> "%OUT%" 2>&1
echo ===== Findings >> "%OUT%"
%CLI% detections --all >> "%OUT%" 2>&1
echo ===== Verify latest DET-001 evidence against the live log >> "%OUT%"
%CLI% verify-evidence --rule DET-001 >> "%OUT%" 2>&1
echo ===== Verify latest COR-001 evidence against the live log >> "%OUT%"
%CLI% verify-evidence --rule COR-001 >> "%OUT%" 2>&1
echo ===== DONE >> "%OUT%"
