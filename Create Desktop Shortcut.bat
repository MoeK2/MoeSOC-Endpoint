@echo off
rem Creates "MoeSOC Endpoint" on your Desktop (run once). Execution policy is
rem bypassed for this one script only; system settings are not changed.
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0launcher\create_shortcut.ps1"
