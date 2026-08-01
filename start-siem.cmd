@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-siem.ps1"
if errorlevel 1 (
  echo.
  echo EDRRR did not start. Review the error above.
  pause
)
endlocal
