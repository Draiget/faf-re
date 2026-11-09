#pragma once

// Engine addition (dedicated-server plan WPL.5): the MSVC CRT <direct.h> calls the shared
// code uses, for the Linux build. There are no drives: every drive's working directory is
// the process's, and the current drive is reported as none (0).

#if defined(_WIN32)
#error "platform/posix/win32/direct.h is for builds without the Windows SDK"
#endif

#include <cstddef>

#include <sys/stat.h>
#include <unistd.h>

inline char* _getcwd(char* const buffer, const int length) noexcept
{
  return ::getcwd(buffer, static_cast<std::size_t>(length));
}

inline char* _getdcwd(int, char* const buffer, const int length) noexcept
{
  return ::getcwd(buffer, static_cast<std::size_t>(length));
}

inline int _getdrive() noexcept
{
  return 0;
}

inline int _mkdir(const char* const path) noexcept
{
  char unixPath[4096];
  std::size_t at = 0;
  for (; path[at] != '\0' && at + 1 < sizeof(unixPath); ++at) {
    unixPath[at] = path[at] == '\\' ? '/' : path[at];
  }
  unixPath[at] = '\0';
  return ::mkdir(unixPath, 0755);
}
