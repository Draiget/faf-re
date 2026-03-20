#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  struct VisibilityRect
  {
    std::int32_t minX;
    std::int32_t minZ;
    std::int32_t maxX;
    std::int32_t maxZ;
  };
  static_assert(sizeof(VisibilityRect) == 0x10, "VisibilityRect size must be 0x10");
} // namespace moho
