#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"

namespace moho
{
  struct SSTICommandSource
  {
    std::uint32_t mIndex; // +0x00
    msvc8::string mName;  // +0x04
    std::int32_t mTimeouts; // +0x20
  };

  static_assert(offsetof(SSTICommandSource, mIndex) == 0x00, "SSTICommandSource::mIndex offset must be 0x00");
  static_assert(offsetof(SSTICommandSource, mName) == 0x04, "SSTICommandSource::mName offset must be 0x04");
  static_assert(offsetof(SSTICommandSource, mTimeouts) == 0x20, "SSTICommandSource::mTimeouts offset must be 0x20");
  static_assert(sizeof(SSTICommandSource) == 0x24, "SSTICommandSource size must be 0x24");
} // namespace moho
