@echo off
setlocal
title LiveAppInspector - live application forensics

rem Resolve the engine whether this launcher sits next to lai.exe (dist\) or one
rem level up in the project root.
set "EXE=%~dp0lai.exe"
if not exist "%EXE%" set "EXE=%~dp0dist\lai.exe"
if not exist "%EXE%" (
  echo ERROR: lai.exe not found next to this script or in .\dist\
  echo Run build.ps1 first.
  pause
  exit /b 1
)

echo Starting LiveAppInspector engine...
echo.
echo   Dashboard opens automatically in your browser.
echo   Global hotkey: Ctrl+Alt+F   (then click any window; Esc cancels)
echo   Close this window or press Ctrl+C to stop the engine.
echo.
"%EXE%" serve --open --port 8787
echo.
echo Engine stopped.
pause
