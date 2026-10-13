@echo off
rem Build the packaged app and (if Inno Setup is installed) the installer.
rem   1. installs PyInstaller into this projects .venv only (development dependency)
rem   2. builds dist\MoeSOC\MoeSOC.exe from packaging\moesoc.spec
rem   3. runs MoeSOC.exe --self-test (no window, no elevation) and records the result
rem   4. builds dist\installer\MoeSOC-Setup-x64.exe with Inno Setup, if it is installed
rem Inno Setup is never installed by this script. Output: build_output.txt
cd /d "%~dp0.."
set PYTHONUTF8=1
set "OUT=%CD%\build_output.txt"
echo MoeSOC build - %DATE% %TIME% > "%OUT%"
if not exist ".venv\Scripts\python.exe" (
  echo .venv not found. Run scripts\verify_windows.bat first. >> "%OUT%"
  exit /b 1
)
echo ===== PyInstaller >> "%OUT%"
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check "pyinstaller>=6.10,<7" >> "%OUT%" 2>&1
if errorlevel 1 ( echo pip install pyinstaller FAILED >> "%OUT%" & exit /b 1 )
".venv\Scripts\python.exe" -m PyInstaller packaging\moesoc.spec --noconfirm --clean --distpath dist --workpath build\pyinstaller >> "%OUT%" 2>&1
if errorlevel 1 ( echo PyInstaller build FAILED >> "%OUT%" & exit /b 1 )
echo ===== Self-test of dist\MoeSOC\MoeSOC.exe >> "%OUT%"
start "" /wait "dist\MoeSOC\MoeSOC.exe" --self-test
echo self-test exit code %ERRORLEVEL% >> "%OUT%"
type "%LOCALAPPDATA%\MoeSOC\logs\self-test.txt" >> "%OUT%" 2>&1
echo ===== Installer >> "%OUT%"
set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not defined ISCC (
  echo Inno Setup 6 is not installed, so no installer was built. >> "%OUT%"
  echo To build it: install Inno Setup 6 ^(e.g. winget install -e --id JRSoftware.InnoSetup^) and run this script again. >> "%OUT%"
  echo DONE ^(executable only^) >> "%OUT%"
  exit /b 0
)
"%ISCC%" packaging\MoeSOC.iss >> "%OUT%" 2>&1
if errorlevel 1 ( echo Inno Setup build FAILED >> "%OUT%" & exit /b 1 )
for %%F in ("dist\installer\MoeSOC-Setup-x64.exe") do echo Installer: %%~fF ^(%%~zF bytes^) >> "%OUT%"
echo DONE >> "%OUT%"
