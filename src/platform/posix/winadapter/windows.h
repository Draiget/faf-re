#pragma once

// Engine addition (issue #255): <windows.h> for the Linux client's files that are compiled with
// DirectX-Headers' Win32 adapter instead of the POSIX <Windows.h> (cmake/FafLinuxClient.cmake:
// faf_client_imaging): DirectXTex brings that adapter, and the two can't meet in one file.

#include <wsl/winadapter.h>
