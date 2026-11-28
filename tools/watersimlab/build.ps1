# Builds the headless lab of the water simulation: tools/watersimlab/watersimlab.exe (MSVC, D3D11 + the shader compiler; no engine code).
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath
$bat = "$vs\VC\Auxiliary\Build\vcvars64.bat"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
cmd /c "`"$bat`" >nul && cd /d `"$here`" && cl /nologo /EHsc /std:c++17 /O2 /Fe:watersimlab.exe watersimlab.cpp d3d11.lib d3dcompiler.lib /link"
