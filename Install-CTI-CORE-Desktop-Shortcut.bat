@echo off
setlocal
set "LAUNCHER=%~dp0Start-CTI-CORE.bat"
if not exist "%LAUNCHER%" (
    echo ERROR: Start-CTI-CORE.bat is missing.
    echo Extract both launcher files into D:\Project\cti-project-final first.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$shell = New-Object -ComObject WScript.Shell; $desktop = [Environment]::GetFolderPath('Desktop'); $shortcut = $shell.CreateShortcut((Join-Path $desktop 'CTI CORE.lnk')); $shortcut.TargetPath = '%LAUNCHER%'; $shortcut.WorkingDirectory = '%~dp0'; $shortcut.Description = 'Start CTI CORE backend and frontend'; $shortcut.Save(); Write-Host 'Created desktop shortcut: CTI CORE'"
if errorlevel 1 (
    echo Could not create the shortcut automatically.
    pause
    exit /b 1
)
echo.
echo Desktop shortcut created. Double-click CTI CORE on your Desktop.
pause
