#pragma once
#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/sim/SFootprint.h"

namespace moho
{
  struct SNamedFootprint : public SFootprint
  {
    msvc8::string mName; // +0x10
    std::int32_t mIndex; // +0x2C
  };

  static_assert(offsetof(SNamedFootprint, mName) == 0x10, "SNamedFootprint::mName offset must be 0x10");
  static_assert(offsetof(SNamedFootprint, mIndex) == 0x2C, "SNamedFootprint::mIndex offset must be 0x2C");
  static_assert(sizeof(SNamedFootprint) == 0x30, "SNamedFootprint size must be 0x30");
} // namespace moho
