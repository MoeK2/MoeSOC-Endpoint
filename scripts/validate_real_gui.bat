@echo off
rem Real-event validation, GUI part (see docs/validation.md). Run after validate_real_auth.bat.
rem Opens the .verify-data validation database only; runs no scan and changes nothing.
rem Output: validation_gui_output.txt, screenshots in docs\screenshots\real-*.png
cd /d "%~dp0.."
set PYTHONUTF8=1
set "OUT=%CD%\validation_gui_output.txt"
echo MoeSOC real-event validation (GUI) - %DATE% %TIME% > "%OUT%"
".venv\Scripts\python.exe" scripts\real_validation_gui.py >> "%OUT%" 2>&1
echo exit code %ERRORLEVEL% >> "%OUT%"
