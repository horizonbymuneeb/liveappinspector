@echo off
setlocal
title LiveAppInspector - elevated

set "EXE=%~dp0lai.exe"
if not exist "%EXE%" set "EXE=%~dp0dist\lai.exe"
if not exist "%EXE%" (
  echo ERROR: lai.exe not found next to this script or in .\dist\
  pause
  exit /b 1
)

echo Requesting Administrator rights (UAC)...
echo Required to inspect SYSTEM, service and protected processes.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%EXE%' -ArgumentList 'serve','--open','--port','8787' -Verb RunAs"
if errorlevel 1 (
  echo.
  echo Elevation failed or was cancelled.
  pause
)
