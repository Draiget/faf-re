@echo off
rem Launches the Tracy Profiler GUI.
if not exist "%~dp0tools\tracy\tracy-profiler.exe" (
  echo Downloading Tracy Profiler v0.11.1...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://github.com/wolfpld/tracy/releases/download/v0.11.1/windows-0.11.1.zip' -OutFile '%~dp0tracy.zip'; Expand-Archive -Path '%~dp0tracy.zip' -DestinationPath '%~dp0tools\tracy' -Force; Remove-Item '%~dp0tracy.zip' -Force"
)
start "" "%~dp0tools\tracy\tracy-profiler.exe" %*
