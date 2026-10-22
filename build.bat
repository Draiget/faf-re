@echo off
rem Builds the engine and copies it into the FAF run folders; see build.ps1 for options.
rem   build.bat                 x64 Release -> C:\ProgramData\FAForever\bin_x64
rem   build.bat -Arch both      x64 and x86 (x86 -> C:\ProgramData\FAForever\bin)
rem   build.bat -Arch x86
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
exit /b %ERRORLEVEL%
