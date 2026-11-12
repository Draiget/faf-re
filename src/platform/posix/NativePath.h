#pragma once

// Engine addition (issue #255): an engine path as a POSIX file call takes it. The engine's native
// paths keep Windows' backslashes and its case-insensitive spelling; the Win32 file calls on POSIX
// (Win32Shim.cpp) convert them, and code that opens files with std::ifstream, fopen or a library
// (the movie player's FFmpeg) converts them here: '/' for '\', and each component as spelled on
// disk when the given case doesn't exist (as NTFS would find it).

#include <string>

namespace platform::posix
{
  [[nodiscard]] std::string NativePath(const char* path);
} // namespace platform::posix
