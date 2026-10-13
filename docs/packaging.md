# Packaging: MoeSOC.exe and MoeSOC-Setup-x64.exe

## Build

```powershell
scripts\build_installer.bat        # writes build_output.txt
```

1. Installs PyInstaller into the project's `.venv` only (a development dependency).
2. Builds `dist\MoeSOC\MoeSOC.exe` from `packaging\moesoc.spec`: one folder, windowed, the icon and a Windows version resource embedded, detection rules and icons bundled, no UPX (UPX-packed executables are often flagged by antivirus heuristics).
3. Runs `MoeSOC.exe --self-test`: no window and no elevation. It checks the version, all rules, the database schema, the icon, pywin32 and builds the main window offscreen, then writes `%LOCALAPPDATA%\MoeSOC\logs\self-test.txt`.
4. If **Inno Setup 6** is installed, builds `dist\installer\MoeSOC-Setup-x64.exe` from `packaging\MoeSOC.iss`. The script never installs Inno Setup; that is your decision (`winget install -e --id JRSoftware.InnoSetup`).

## How the packaged app starts (`moesoc/frozen.py`)

The source version uses `launcher\launch_moesoc.py`; the executable does the same work itself, reusing the launcher's Win32 helpers and the same single-instance mutex:

- already running → the existing window comes to the front (no UAC prompt);
- not elevated → the standard Windows UAC prompt once; the elevated copy continues with `--elevated` and never asks again;
- UAC declined → MoeSOC still opens, and the Overview shows it is not elevated (reading the Security log needs administrator rights);
- the taskbar shows the MoeSOC icon (explicit AppUserModelID).

## Installer

- Per-machine install to `Program Files\MoeSOC Endpoint` (one UAC prompt during setup), Start-menu shortcut, optional desktop shortcut, "Start MoeSOC" at the end.
- Shows a short notice before installing: read-only, local, no audit-policy changes, no Sysmon install, no blocking or quarantine, data location.
- Uninstall removes the program files only. MoeSOC data in `%LOCALAPPDATA%\MoeSOC` (database, logs) is kept; delete it yourself if you want it gone. Windows event logs are never touched.

## Status (October 8, 2026, Windows 11 development PC)

| Item | Status |
|---|---|
| `MoeSOC.exe` built with PyInstaller 6 | TESTED: build log in `build_output.txt` |
| `MoeSOC.exe --self-test` | TESTED: passed (12 rules, schema v8, icon, pywin32, main window with 9 pages built offscreen) |
| Start-up decisions (UAC once, declined, already running, lock race) | TESTED with a fake platform (`tests/test_frozen.py`); real UAC prompt: manual queue |
| `MoeSOC-Setup-x64.exe` | BLOCKED BY ENVIRONMENT: Inno Setup 6 is not installed on the build PC (installing it is the owner's decision) |
| Code signing | NOT DONE: needs a code-signing certificate. Unsigned executables show a SmartScreen warning on first run |
