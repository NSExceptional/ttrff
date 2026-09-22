' ttrff.vbs -- no-console launcher for the ttrff tray app (Windows).
'
' Used by the Start Menu shortcut (Scoop `shortcuts`) so launching from Windows
' Search / the Start Menu doesn't flash a console window: WScript.Shell.Run with
' the window style 0 (hidden) starts bin\ttrff.cmd --hidden, which runs the tray
' under pythonw (no console). The tray itself is a single-instance app -- a second
' launch just exits, so double-clicking the shortcut repeatedly is harmless.
'
' Deliberately plain VBScript (no args parsing): the shortcut always launches the
' tray the same way. For a console run with output (e.g. --selftest), use the
' `ttrff` shim on PATH instead.
Dim appdir, shell, fso
Set fso = CreateObject("Scripting.FileSystemObject")
appdir = fso.GetParentFolderName(fso.GetParentFolderName(WScript.ScriptFullName))
Set shell = CreateObject("WScript.Shell")
shell.Run """" & appdir & "\bin\ttrff.cmd"" --hidden", 0, False
