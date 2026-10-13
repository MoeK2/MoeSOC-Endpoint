# Creates "MoeSOC Endpoint.lnk" on the current user's Desktop.
# Run it yourself (double-click "Create Desktop Shortcut.bat"); nothing else creates shortcuts.
# All paths come from this script's location. A .lnk file itself stores absolute paths
# (that is how Windows shortcuts work), so re-run this if you move the project folder.
$ErrorActionPreference = "Stop"

$launcherDir = $PSScriptRoot
$projectDir  = Split-Path -Parent $launcherDir
$vbs         = Join-Path $launcherDir "MoeSOC.vbs"
$desktop     = [Environment]::GetFolderPath("Desktop")   # follows OneDrive redirection
$linkPath    = Join-Path $desktop "MoeSOC Endpoint.lnk"
$wscript     = Join-Path $env:WINDIR "System32\wscript.exe"

$shell = New-Object -ComObject WScript.Shell
try {
    if (-not (Test-Path $vbs)) { throw "Launcher not found: $vbs" }

    # Icon: use a project .ico if one exists (assets\icons\*.ico); otherwise the Python icon.
    $icon = Get-ChildItem -Path (Join-Path $projectDir "assets") -Filter *.ico -Recurse `
        -ErrorAction SilentlyContinue | Select-Object -First 1
    $pythonw = Join-Path $projectDir ".venv\Scripts\pythonw.exe"

    $link = $shell.CreateShortcut($linkPath)
    $link.TargetPath       = $wscript
    $link.Arguments        = "`"$vbs`""
    $link.WorkingDirectory = $projectDir
    $link.Description      = "MoeSOC Endpoint - Windows host-based detection and investigation"
    if ($icon) { $link.IconLocation = "$($icon.FullName),0" }
    elseif (Test-Path $pythonw) { $link.IconLocation = "$pythonw,0" }
    $link.Save()

    $null = $shell.Popup("Created on your Desktop:`n$linkPath`n`nDouble-click it to start MoeSOC.", 0, "MoeSOC Endpoint", 64)
    exit 0
}
catch {
    $null = $shell.Popup("The shortcut could not be created:`n$($_.Exception.Message)", 0, "MoeSOC Endpoint", 16)
    exit 1
}
