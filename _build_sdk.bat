@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat" 1>nul
cd /d G:\projects\faf-main
msbuild src\sdk\sdk.vcxproj /t:Build /p:Configuration=Debug /p:Platform=Win32 /m /nologo /v:minimal
