' MoeSOC Endpoint - windowless entry point (run by wscript.exe, so no console appears).
' Resolves the project folder from this file's location, checks the environment,
' then hands over to launcher\launch_moesoc.py (elevation, single instance, diagnostics).
Option Explicit

Const TITLE = "MoeSOC Endpoint"
Dim fso, shellApp, launcherDir, projectDir, pythonw, launcherPy, setupScript, answer

Set fso = CreateObject("Scripting.FileSystemObject")
Set shellApp = CreateObject("Shell.Application")

launcherDir = fso.GetParentFolderName(WScript.ScriptFullName)
projectDir = fso.GetParentFolderName(launcherDir)
pythonw = fso.BuildPath(projectDir, ".venv\Scripts\pythonw.exe")
launcherPy = fso.BuildPath(launcherDir, "launch_moesoc.py")
setupScript = fso.BuildPath(projectDir, "scripts\verify_windows.bat")

If Not fso.FileExists(pythonw) Then
    If fso.FileExists(setupScript) Then
        answer = MsgBox("MoeSOC environment is not installed." & vbCrLf & vbCrLf & _
            "Run setup before starting MoeSOC." & vbCrLf & vbCrLf & _
            "Run setup now? It creates the environment and runs the checks " & _
            "(a few minutes; results go to verify_output.txt).", _
            vbYesNo + vbExclamation, TITLE)
        If answer = vbYes Then
            shellApp.ShellExecute setupScript, "", projectDir, "open", 1
        End If
    Else
        MsgBox "MoeSOC environment is not installed." & vbCrLf & vbCrLf & _
            "Run setup before starting MoeSOC.", vbExclamation, TITLE
    End If
    WScript.Quit 1
End If

If Not fso.FileExists(launcherPy) Then
    MsgBox "MoeSOC could not start." & vbCrLf & vbCrLf & _
        "Missing launcher file:" & vbCrLf & launcherPy, vbCritical, TITLE
    WScript.Quit 1
End If

' Working directory = project folder, never the folder Windows started us from.
shellApp.ShellExecute pythonw, """" & launcherPy & """", projectDir, "open", 1
