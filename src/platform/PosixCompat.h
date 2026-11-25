#pragma once

#include "PlatformDefines.h"

// Engine addition (the macOS and Android ports): every thread this code starts goes through
// platform/posix/FpEnvPosix.cpp's faf_pthread_create on macOS and Android, std::thread's included
// (libc++ starts it with an inline call to pthread_create in our own objects), for Linux's 8 MB
// stack. macOS gives a new thread 512 KB, and saving the sim needs more; bionic gives about 1 MB,
// half the x86 binary's 2 MB and a quarter of the 4 MB the x64 build reserves for its wider frames
// (/STACK, src/CMakeLists.txt). A macro, as Apple's linker has no --wrap; on Android x86_64 the call
// goes on through FpEnvPosix.cpp's --wrap of pthread_create.
#if FAFRE_PLATFORM_MACOS || FAFRE_PLATFORM_ANDROID // default thread stacks: macOS 512 KB, bionic 1 MB
#define pthread_create faf_pthread_create
#endif

// Engine addition (dedicated-server plan WPL.5): the Windows names the shared simulation
// code uses from <Windows.h> and the MSVC CRT, for builds without them (Linux). The Linux
// build force-includes this header (cmake/FafPosix.cmake); Windows builds never see it.
// Each name means what it means on Windows.

#if !FAFRE_PLATFORM_WINDOWS && defined(__cplusplus)

#include <cstddef>
#include <cstdint>
#include <strings.h>
#include <time.h>

// Windows headers reach the shared code through other headers, so names such as HANDLE,
// DWORD and FILETIME are used in files that never include <Windows.h> themselves; this
// build provides them everywhere, as the Windows build effectively does.
#include <Windows.h>

// std::atomic_ref where the C++ library lacks it (libc++ 18).
#include "platform/posix/AtomicRefPolyfill.h"

using LONGLONG = std::int64_t;
using ULONGLONG = std::uint64_t;

#define LOBYTE(w) (static_cast<std::uint8_t>(static_cast<std::uintptr_t>(w) & 0xFFu))
#define HIBYTE(w) (static_cast<std::uint8_t>((static_cast<std::uintptr_t>(w) >> 8) & 0xFFu))
#define MAKEWORD(a, b) (static_cast<std::uint16_t>(LOBYTE(a) | (static_cast<std::uint16_t>(LOBYTE(b)) << 8)))

inline int _stricmp(
  const char* const lhs,
  const char* const rhs
) noexcept
{
  return ::strcasecmp(lhs, rhs);
}

inline int _strnicmp(
  const char* const lhs,
  const char* const rhs,
  const std::size_t count
) noexcept
{
  return ::strncasecmp(lhs, rhs, count);
}

#endif // !defined(_WIN32) && defined(__cplusplus)
