#pragma once

// Engine addition (issue #255): <objbase.h> for the Linux client. The client starts COM on the
// threads that use XACT and the texture codec; on Linux neither is COM (FAudio, DirectXTex's CPU
// code), so there is nothing to start or stop.

#if FAFRE_PLATFORM_WINDOWS
#error "platform/posix/win32/objbase.h is for builds without the Windows SDK"
#endif

#include <Windows.h>

#define COINIT_MULTITHREADED 0x0u
#define COINIT_APARTMENTTHREADED 0x2u

inline HRESULT CoInitializeEx(void* const reserved, const DWORD flags) noexcept
{
  (void)reserved;
  (void)flags;
  return S_OK;
}

inline void CoUninitialize() noexcept {}
