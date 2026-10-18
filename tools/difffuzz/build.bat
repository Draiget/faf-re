@echo off
rem ---------------------------------------------------------------------------
rem difffuzz build: a standalone 32-bit console tool. It never touches
rem src\sdk\main.vcxproj; it compiles the few recovered math TUs it tests
rem straight from src\sdk with the same float-relevant switches main.vcxproj
rem uses for Win32 (v143 defaults /arch:SSE2 /fp:precise, C++20, and in
rem Release /O2 + the forced-include platform\X87SqrtCall.h).
rem
rem   build.bat            -> build\difffuzz_release.exe and build\difffuzz_debug.exe
rem   build.bat release    -> only the Release-flavoured exe
rem   build.bat debug      -> only the Debug-flavoured exe
rem
rem The exe is linked at /BASE:0x10000000 /DYNAMICBASE:NO so the retail image
rem can be mapped at its own preferred base 0x00400000 (it has no relocations).
rem ---------------------------------------------------------------------------
setlocal EnableDelayedExpansion

set "HERE=%~dp0"
for %%I in ("%HERE%..\..") do set "REPO=%%~fI"
set "SDK=%REPO%\src\sdk"
set "WM3=%REPO%\dependencies\WildMagic3p8\Foundation"
set "OUT=%HERE%build"

if not defined VCToolsInstallDir (
  call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat" >nul
  if errorlevel 1 ( echo vcvarsamd64_x86.bat failed & exit /b 1 )
)

if not exist "%OUT%" mkdir "%OUT%"

set "WHICH=%~1"
if "%WHICH%"=="" set "WHICH=all"

set "INC=/I "%SDK%" /I "%WM3%" /I "%WM3%\Math" /I "%WM3%\System" /I "%WM3%\ObjectSystem" /I "%HERE%src""
set "COMMON=/nologo /c /std:c++20 /permissive- /Zc:inline /fp:precise /EHsc /W3 /sdl /GS /wd4073 /wd4244 /wd4273 /wd4834 /wd4996 /D WIN32 /D _CONSOLE /D WIN32_LEAN_AND_MEAN /D NOMINMAX /D _CRT_SECURE_NO_WARNINGS /D BOOST_ALL_NO_LIB %INC%"

rem Recovered engine sources under test - compiled from src\sdk, not copied.
set "SDK_SRCS="%SDK%\moho\math\QuaternionMath.cpp" "%SDK%\moho\math\Vector3f.cpp" "%SDK%\legacy\math\X87Math.cpp" "%WM3%\System\Wm3System.cpp""
rem Harness sources.
set "H_SRCS="%HERE%src\main.cpp" "%HERE%src\pe_image.cpp" "%HERE%src\retail_thunks.cpp" "%HERE%src\targets_math.cpp" "%HERE%src\gen.cpp" "%HERE%src\sdk_mirror.cpp""

set "LINKFLAGS=/nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 /BASE:0x10000000 /FIXED:NO /DYNAMICBASE:NO /NXCOMPAT /INCREMENTAL:NO /DEBUG"

if /I "%WHICH%"=="all"     call :build release || exit /b 1
if /I "%WHICH%"=="all"     call :build debug   || exit /b 1
if /I "%WHICH%"=="release" call :build release || exit /b 1
if /I "%WHICH%"=="debug"   call :build debug   || exit /b 1
echo build OK
exit /b 0

:build
set "CFG=%~1"
set "OBJ=%OUT%\obj_%CFG%"
if not exist "%OBJ%" mkdir "%OBJ%"
if /I "%CFG%"=="release" (
  rem main.vcxproj Release^|Win32: /O2 (implies /Oi), /Gy, release CRT,
  rem ForcedIncludeFiles platform\X87SqrtCall.h.
  set "CFGFLAGS=/O2 /Oi /Gy /MD /D NDEBUG /FI platform\X87SqrtCall.h"
) else (
  rem main.vcxproj Debug^|Win32: /Od /Ob1, no RTC, no JMC, debug CRT.
  set "CFGFLAGS=/Od /Ob1 /MDd /D _DEBUG /D _ITERATOR_DEBUG_LEVEL=0"
)
echo [difffuzz] compiling %CFG%
cl %COMMON% !CFGFLAGS! /Zi /Fd"%OBJ%\vc.pdb" /Fo"%OBJ%\\" %SDK_SRCS% %H_SRCS%
if errorlevel 1 exit /b 1
link %LINKFLAGS% /OUT:"%OUT%\difffuzz_%CFG%.exe" "%OBJ%\*.obj"
if errorlevel 1 exit /b 1
exit /b 0
