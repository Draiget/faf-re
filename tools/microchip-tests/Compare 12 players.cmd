@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-Classic-Test.ps1" -Players 12 -Compare -Pause
