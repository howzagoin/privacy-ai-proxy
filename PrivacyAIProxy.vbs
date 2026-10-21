' PrivacyAIProxy.vbs
' Launches privacy_proxy.py silently in the background on Windows without opening a command prompt window.

Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")

' Dynamically locate the directory where this script is located
scriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
proxyScript = FSO.BuildPath(scriptDir, "privacy_proxy.py")

WshShell.CurrentDirectory = scriptDir
WshShell.Run "cmd.exe /c start """" /b pythonw """ & proxyScript & """", 0, False

Set FSO = Nothing
Set WshShell = Nothing
