#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>

// The texel of the terrain's water level map: what the terrain effect reads of a map with water bodies instead of the
// water map's baked depth (docs/WATER_SIMULATION.md, "The tint under the water"). One 32-bit texel per 2 x 2 block (the
// water map's blocks), the level of the block's water in the low 16 bits and its abyss in the high 16 bits, both in
// 1/128 world unit (the height field's own unit; 0xFFFF = no water). The shader (TerrainWaterLevelPatch.cpp) mirrors
// TexelDepth: the depth of a pixel is computed from its own terrain height, so the tint follows the shore exactly and
// the 2-unit grid of the baked depth is gone. Pure C++ so the packing and the formula are tested without a device.
namespace moho::water
{
  constexpr float kNoWaterLevel = -10000.0f; // the engine's kWaterBodyNoWater
  constexpr std::uint32_t kNoWaterRaw = 0xFFFFu;
  constexpr float kLevelUnit = 1.0f / 128.0f;

  // Levels and abysses at or below zero cannot matter (the heights are unsigned): stored as 0.
  [[nodiscard]] inline std::uint32_t PackRaw16(
    const float value
  ) noexcept
  {
    if (!(value > -1000.0f)) {
      return kNoWaterRaw;
    }
    const float units = std::floor(value / kLevelUnit + 0.5f);
    return static_cast<std::uint32_t>(std::min(std::max(units, 0.0f), 65534.0f));
  }

  [[nodiscard]] inline std::uint32_t PackLevelTexel(
    const float level,
    const float abyss
  ) noexcept
  {
    return PackRaw16(level) | (PackRaw16(abyss) << 16u);
  }

  // The depth the terrain shader tints with, 0 .. 1: (level - height) / (level - abyss), as the baked depth was, but at
  // the pixel's own height. 0 where the block has no water or the pixel is above its water.
  [[nodiscard]] inline float TexelDepth(
    const std::uint32_t texel,
    const float height
  ) noexcept
  {
    const std::uint32_t levelRaw = texel & 0xFFFFu;
    if (levelRaw == kNoWaterRaw) {
      return 0.0f;
    }
    const std::uint32_t abyssRaw = texel >> 16u;
    const float level = static_cast<float>(levelRaw) * kLevelUnit;
    const float abyss = abyssRaw == kNoWaterRaw ? 0.0f : static_cast<float>(abyssRaw) * kLevelUnit;
    const float depth = (level - height) / std::max(level - abyss, 0.01f);
    return std::min(std::max(depth, 0.0f), 1.0f);
  }
} // namespace moho::water
