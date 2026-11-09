@echo off
rem Retail call recorder: x86 (the original ForgedAlliance.exe is 32-bit).
rem   build\recorder.dll  injected into the game
rem   build\recorder.exe  starts the game with the DLL loaded
setlocal
set "HERE=%~dp0"
set "OUT=%HERE%build"
if not defined VCToolsInstallDir (
  call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat" >nul
  if errorlevel 1 ( echo vcvarsamd64_x86.bat failed & exit /b 1 )
)
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /O2 /MT /W3 /D WIN32_LEAN_AND_MEAN /D _CRT_SECURE_NO_WARNINGS /LD /Fo"%OUT%\\" /Fe"%OUT%\recorder.dll" "%HERE%recorder_dll.cpp" || exit /b 1
cl /nologo /std:c++20 /EHsc /O2 /MT /W3 /D WIN32_LEAN_AND_MEAN /D _CRT_SECURE_NO_WARNINGS /D UNICODE /Fo"%OUT%\\" /Fe"%OUT%\recorder.exe" "%HERE%launcher.cpp" user32.lib || exit /b 1
echo build OK
