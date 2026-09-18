@echo off
rem Build scripts\stackdump.cpp as a 32-bit exe so it can walk main.exe's
rem threads (main.exe is Win32; a 64-bit walker cannot StackWalk64 a WOW64
rem process's 32-bit frames correctly).
rem
rem Output lands next to the staged binary so main.pdb resolves without a
rem search path argument.

setlocal
set VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars32.bat
set OUTDIR=%~1
if "%OUTDIR%"=="" set OUTDIR=C:\ProgramData\FAForever\bin

call "%VCVARS%" >nul
if errorlevel 1 (
  echo failed to initialise the 32-bit toolchain
  exit /b 1
)

cl.exe /nologo /EHsc /O2 /W3 /D_CRT_SECURE_NO_WARNINGS ^
  "%~dp0stackdump.cpp" ^
  /Fe"%OUTDIR%\stackdump.exe" ^
  /Fo"%TEMP%\stackdump.obj" ^
  /link dbghelp.lib

if errorlevel 1 (
  echo build failed
  exit /b 1
)

echo built %OUTDIR%\stackdump.exe
endlocal
