@echo off
rem Runs the same commands as .github/workflows/ci.yml (test job + executable self-test)
rem on this PC, including the offscreen GUI mode used on the CI runner.
rem Output: ci_local_output.txt. Read-only, like CI.
cd /d "%~dp0.."
set PYTHONUTF8=1
set "OUT=%CD%\ci_local_output.txt"
set "VPY=%CD%\.venv\Scripts\python.exe"
echo MoeSOC local CI - %DATE% %TIME% > "%OUT%"
echo ===== Ruff >> "%OUT%"
"%VPY%" -m ruff check . >> "%OUT%" 2>&1 || echo STEP FAILED: ruff check >> "%OUT%"
"%VPY%" -m ruff format --check . >> "%OUT%" 2>&1 || echo STEP FAILED: ruff format >> "%OUT%"
echo ===== Tests >> "%OUT%"
"%VPY%" -m pytest -q -rs --basetemp "%CD%\.pytest-tmp" >> "%OUT%" 2>&1 || echo STEP FAILED: pytest >> "%OUT%"
echo ===== CLI >> "%OUT%"
"%VPY%" -m moesoc.cli --data-dir ci-data health >> "%OUT%" 2>&1
"%VPY%" -m moesoc.cli --data-dir ci-data scan >> "%OUT%" 2>&1
"%VPY%" -m moesoc.cli --data-dir ci-data detections --all >> "%OUT%" 2>&1
echo ===== GUI smoke (offscreen, as on the CI runner) >> "%OUT%"
set QT_QPA_PLATFORM=offscreen
"%VPY%" scripts\gui_smoke.py >> "%OUT%" 2>&1 || echo STEP FAILED: gui smoke >> "%OUT%"
set QT_QPA_PLATFORM=
echo ===== Executable self-test (if built) >> "%OUT%"
if exist "dist\MoeSOC\MoeSOC.exe" (
  powershell -NoProfile -Command "$p = Start-Process -FilePath dist\MoeSOC\MoeSOC.exe -ArgumentList --self-test -Wait -PassThru; exit $p.ExitCode" >> "%OUT%" 2>&1
  echo self-test exit code %ERRORLEVEL% >> "%OUT%"
  type "%LOCALAPPDATA%\MoeSOC\logs\self-test.txt" >> "%OUT%" 2>&1
) else ( echo dist\MoeSOC\MoeSOC.exe not built - run scripts\build_installer.bat >> "%OUT%" )
echo ===== DONE >> "%OUT%"
