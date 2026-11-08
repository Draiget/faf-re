#pragma once

// Writes a whole buffer to a file or reports that it couldn't, for the save writers.

#include <cstddef>
#include <cstdio>

namespace moho
{
  [[nodiscard]] inline bool WriteExact(std::FILE* const file, const void* const data, const std::size_t byteCount)
  {
    if (!file) {
      return false;
    }
    if (byteCount == 0) {
      return true;
    }
    return std::fwrite(data, byteCount, 1, file) == 1;
  }
} // namespace moho
