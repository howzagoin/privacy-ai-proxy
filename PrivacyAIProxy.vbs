' PrivacyAIProxy.vbs
' Launches privacy_proxy.py silently in the background on Windows startup without opening a console window.

Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\Users\Timothy.MacLatchy\GitHubRepos\tools"
WshShell.Run "cmd.exe /c start """" /b ""C:\Python314\pythonw.exe"" ""C:\Users\Timothy.MacLatchy\GitHubRepos\tools\privacy_proxy.py""", 0, False
Set WshShell = Nothing
