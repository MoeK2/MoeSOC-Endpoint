@echo off
rem MoeSOC Windows verification: venv, lint, tests, CLI, GUI smoke test.
rem All output goes to verify_output.txt in the project folder.
rem Uses a separate .verify-data folder; your real MoeSOC data is not touched.
setlocal
cd /d "%~dp0.."
set "OUT=%CD%\verify_output.txt"
set PYTHONUTF8=1

echo MoeSOC verification - %DATE% %TIME% > "%OUT%"
echo Folder: %CD% >> "%OUT%"
net session >nul 2>&1 && (echo Elevated: YES >> "%OUT%") || (echo Elevated: NO >> "%OUT%")

set "PY="
py -3.13 --version >nul 2>&1 && set "PY=py -3.13"
if not defined PY (py -3 --version >nul 2>&1 && set "PY=py -3")
if not defined PY (python --version >nul 2>&1 && set "PY=python")
if not defined PY (
  echo Python is not on PATH. Searching common install locations... >> "%OUT%"
  for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*" "%ProgramFiles%\Python3*" "C:\Python3*" "%USERPROFILE%\anaconda3" "%USERPROFILE%\miniconda3") do (
    if exist "%%~D\python.exe" (
      echo   found: %%~D\python.exe >> "%OUT%"
      set "PY="%%~D\python.exe""
    )
  )
)
if not defined PY (
  echo ===== Installing Python 3.13 per-user with winget >> "%OUT%"
  winget install -e --id Python.Python.3.13 --scope user --silent --accept-package-agreements --accept-source-agreements >> "%OUT%" 2>&1
  if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PY="%LOCALAPPDATA%\Programs\Python\Python313\python.exe""
)
if not defined PY (
  echo --- diagnostics --- >> "%OUT%"
  assoc .py >> "%OUT%" 2>&1
  ftype Python.File >> "%OUT%" 2>&1
  reg query HKCU\Software\Python /s /v ExecutablePath >> "%OUT%" 2>&1
  reg query HKLM\Software\Python /s /v ExecutablePath >> "%OUT%" 2>&1
  where /r "%LOCALAPPDATA%\Programs" python.exe >> "%OUT%" 2>&1
)
if not defined PY (
  echo ERROR: Python not found. Install Python 3.12+ from python.org. >> "%OUT%"
  goto :end
)
echo Python launcher: %PY% >> "%OUT%"
%PY% --version >> "%OUT%" 2>&1

if not exist .venv\Scripts\python.exe (
  echo ===== Creating virtual environment >> "%OUT%"
  %PY% -m venv .venv >> "%OUT%" 2>&1
)
set "VPY=%CD%\.venv\Scripts\python.exe"
if not exist "%VPY%" (
  echo ERROR: virtual environment creation failed. >> "%OUT%"
  goto :end
)

echo ===== Installing dependencies >> "%OUT%"
"%VPY%" -m pip install --disable-pip-version-check -q -r requirements-dev.txt >> "%OUT%" 2>&1
"%VPY%" -c "import PySide6, yaml, win32evtlog; print('PySide6', PySide6.__version__)" >> "%OUT%" 2>&1

echo ===== RUFF CHECK >> "%OUT%"
"%VPY%" -m ruff check . >> "%OUT%" 2>&1
echo ===== RUFF FORMAT >> "%OUT%"
"%VPY%" -m ruff format --check . >> "%OUT%" 2>&1

echo ===== PYTEST >> "%OUT%"
"%VPY%" -m pytest -v -rs --basetemp "%CD%\.pytest-tmp" >> "%OUT%" 2>&1

echo ===== CLI health >> "%OUT%"
"%VPY%" -m moesoc.cli --data-dir .verify-data health >> "%OUT%" 2>&1
echo ===== CLI scan (real Security log, last 24 h) >> "%OUT%"
"%VPY%" -m moesoc.cli --data-dir .verify-data scan >> "%OUT%" 2>&1
echo exit code %ERRORLEVEL% >> "%OUT%"
echo ===== CLI events >> "%OUT%"
"%VPY%" -m moesoc.cli --data-dir .verify-data events --limit 10 >> "%OUT%" 2>&1
echo ===== CLI detections >> "%OUT%"
"%VPY%" -m moesoc.cli --data-dir .verify-data detections >> "%OUT%" 2>&1

echo ===== GUI SMOKE TEST >> "%OUT%"
"%VPY%" scripts\gui_smoke.py >> "%OUT%" 2>&1
echo exit code %ERRORLEVEL% >> "%OUT%"

:end
echo ===== DONE >> "%OUT%"
endlocal
