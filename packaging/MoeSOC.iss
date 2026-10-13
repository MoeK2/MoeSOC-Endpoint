; Inno Setup script: builds dist\installer\MoeSOC-Setup-x64.exe from dist\MoeSOC\.
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" packaging\MoeSOC.iss
; Installs per machine into Program Files (one UAC prompt during setup).
; Uninstall removes the program files only. Your MoeSOC data in %LOCALAPPDATA%\MoeSOC
; (database, logs) is kept, and Windows event logs are never touched.

#define AppName "MoeSOC Endpoint"
#define AppVersion "1.1.0"
#define AppExe "MoeSOC.exe"

[Setup]
AppId={{C2119D76-6026-4BA3-97FD-339903F6446F}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=MoeSOC project
DefaultDirName={autopf}\MoeSOC Endpoint
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist\installer
OutputBaseFilename=MoeSOC-Setup-x64
SetupIconFile=..\assets\icons\MoeSOC.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

InfoBeforeFile=installer-notes.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "..\dist\MoeSOC\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"; IconFilename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Start {#AppName}"; Flags: nowait postinstall skipifsilent
