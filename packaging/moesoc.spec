# PyInstaller spec for MoeSOC Endpoint (one-folder, windowed).
#   .venv\Scripts\pyinstaller packaging\moesoc.spec --noconfirm --clean
# Output: one folder, dist\MoeSOC, with three programs sharing one _internal folder:
#   MoeSOC.exe        the console (PySide6 GUI, opened on demand)
#   MoeSOCSensor.exe  the Windows service + its management commands (no Qt)
#   MoeSOCTray.exe    the notification-area icon (pywin32 only, no Qt)
# The installer (packaging\MoeSOC.iss) packs that folder. Data files: detection rules
# and the icon. Nothing else is added.
from pathlib import Path

ROOT = Path(SPECPATH).parent  # noqa: F821 - provided by PyInstaller

a = Analysis(  # noqa: F821
    [str(ROOT / "app.py")],
    pathex=[str(ROOT), str(ROOT / "launcher")],  # launcher: shared Win32 start-up helpers
    datas=[
        (str(ROOT / "rules"), "rules"),
        (str(ROOT / "assets" / "icons"), "assets/icons"),
    ],
    hiddenimports=["launch_moesoc", "win32evtlog", "win32api", "win32net", "win32service"],
    excludes=["tkinter", "pytest", "PIL"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="MoeSOC",
    icon=str(ROOT / "assets" / "icons" / "MoeSOC.ico"),
    version=str(ROOT / "packaging" / "version_info.txt"),
    console=False,  # windowed: no console window
    uac_admin=False,  # elevation is requested at start-up (see moesoc/frozen.py)
    upx=False,  # UPX-packed binaries are often flagged by antivirus heuristics
)

SERVICE_IMPORTS = [
    "servicemanager", "win32timezone", "win32serviceutil", "win32service", "win32event",
    "win32evtlog", "win32api", "win32pipe", "win32file", "win32security", "ntsecuritycon",
    "win32net", "win32con", "winerror", "pywintypes", 
]
NO_QT = ["tkinter", "pytest", "PIL", "PySide6", "shiboken6"]

sensor_a = Analysis(  # noqa: F821
    [str(ROOT / "sensor.py")],
    pathex=[str(ROOT)],
    datas=[(str(ROOT / "rules"), "rules")],
    hiddenimports=SERVICE_IMPORTS,
    excludes=NO_QT,
    noarchive=False,
)
sensor_exe = EXE(  # noqa: F821
    PYZ(sensor_a.pure),  # noqa: F821
    sensor_a.scripts,
    [],
    exclude_binaries=True,
    name="MoeSOCSensor",
    icon=str(ROOT / "assets" / "icons" / "MoeSOC.ico"),
    version=str(ROOT / "packaging" / "version_info.txt"),
    console=True,  # management commands print to the administrator prompt; the service
    uac_admin=False,  # itself runs in session 0 without any window
    upx=False,
)

tray_a = Analysis(  # noqa: F821
    [str(ROOT / "tray.py")],
    pathex=[str(ROOT)],
    datas=[(str(ROOT / "assets" / "icons"), "assets/icons")],
    hiddenimports=["win32gui", "win32api", "win32con", "win32event", "win32pipe", "win32file", 
                   "win32security", "winerror", "pywintypes"],
    excludes=NO_QT,
    noarchive=False,
)
tray_exe = EXE(  # noqa: F821
    PYZ(tray_a.pure),  # noqa: F821
    tray_a.scripts,
    [],
    exclude_binaries=True,
    name="MoeSOCTray",
    icon=str(ROOT / "assets" / "icons" / "MoeSOC.ico"),
    version=str(ROOT / "packaging" / "version_info.txt"),
    console=False,
    uac_admin=False,
    upx=False,
)

coll = COLLECT(  # noqa: F821
    exe, a.binaries, a.datas,
    sensor_exe, sensor_a.binaries, sensor_a.datas,
    tray_exe, tray_a.binaries, tray_a.datas,
    name="MoeSOC", upx=False,
)
