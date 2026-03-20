#pragma once

#include <cstdint>

namespace moho
{
  template <typename T>
  struct SMinMax
  {
    T min{};
    T max{};
  };

  static_assert(sizeof(SMinMax<std::uint16_t>) == 0x4, "SMinMax<uint16_t> size must be 0x4");
  static_assert(sizeof(SMinMax<std::uint32_t>) == 0x8, "SMinMax<uint32_t> size must be 0x8");
  static_assert(sizeof(SMinMax<float>) == 0x8, "SMinMax<float> size must be 0x8");
} // namespace moho
