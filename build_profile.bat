@echo off
rem Builds the engine with Tracy profiler enabled (Preset: clang-x64-profile / clang-x86-profile).
rem   build_profile.bat                 x64 Profile -> C:\ProgramData\FAForever\bin_x64\main_x64.exe
rem   build_profile.bat -Arch both      x64 and x86 Profile
rem   build_profile.bat -NoCopy         Build only without copying
rem   build_profile.bat -Name main_prof Custom output name
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" -Profile %*
exit /b %ERRORLEVEL%
