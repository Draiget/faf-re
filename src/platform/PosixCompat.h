#pragma once

// Engine addition (dedicated-server plan WPL.5): the Windows names the shared simulation
// code uses from <Windows.h> and the MSVC CRT, for builds without them (Linux). The Linux
// build force-includes this header (cmake/FafLinux.cmake); Windows builds never see it.
// Each name means what it means on Windows.

#if !defined(_WIN32)

#include <cstddef>
#include <cstdint>
#include <strings.h>
#include <time.h>

// glibc's <time.h> defines TIME_UTC (C11); boost 1.34.1's boost/thread/xtime.hpp declares
// an enumerator of that name (`enum xtime_clock_types { TIME_UTC=1 }`) and uses it.
#undef TIME_UTC

// Windows headers reach the shared code through other headers, so names such as HANDLE,
// DWORD and FILETIME are used in files that never include <Windows.h> themselves; this
// build provides them everywhere, as the Windows build effectively does.
#include <Windows.h>

using LONGLONG = std::int64_t;
using ULONGLONG = std::uint64_t;

#define LOBYTE(w) (static_cast<std::uint8_t>(static_cast<std::uintptr_t>(w) & 0xFFu))
#define HIBYTE(w) (static_cast<std::uint8_t>((static_cast<std::uintptr_t>(w) >> 8) & 0xFFu))
#define MAKEWORD(a, b) \
  (static_cast<std::uint16_t>(LOBYTE(a) | (static_cast<std::uint16_t>(LOBYTE(b)) << 8)))

inline int _stricmp(const char* const lhs, const char* const rhs) noexcept
{
  return ::strcasecmp(lhs, rhs);
}

inline int _strnicmp(const char* const lhs, const char* const rhs, const std::size_t count) noexcept
{
  return ::strncasecmp(lhs, rhs, count);
}

#endif // !defined(_WIN32)
