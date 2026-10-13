@echo off
rem Fallback launcher: same as the Desktop shortcut. The console closes immediately;
rem launcher\MoeSOC.vbs handles the environment check, UAC and error dialogs.
start "" "%WINDIR%\System32\wscript.exe" "%~dp0launcher\MoeSOC.vbs"
