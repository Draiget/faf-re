#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <vector>

// The water level of each 2 x 2 block of a map with water bodies, for the light field (docs/LIGHTING_V2.md "Water
// bodies"). A map with bodies has a level per water (the sea and each lake or pool): the light a point receives
// through the water above it, the surface the field's layers hang from and the depth the sun is dimmed over all need
// the level of the water over that point, not one number for the map. The field's compute shader reads the level
// from the words appended to its height buffer: one 16-bit value per block (1 / 128 world unit, like the heights),
// the block order of the water map (the texel of a block is the vertex pair 2 * block). Pure C++ so the packing and
// the lookups the shader mirrors can be tested without a device.
namespace moho::lights
{
  // "No water here" (a dry body, or the sea of a map without one): the engine's kWaterBodyNoWater.
  constexpr float kNoWaterLevel = -10000.0f;
  constexpr std::uint16_t kNoWaterRaw = 0xFFFFU;
  constexpr float kWaterLevelUnit = 1.0f / 128.0f;

  // The level of the block whose first corner is the vertex (x, z).
  using WaterBlockLevelFunction = float (*)(const void* context, std::int32_t x, std::int32_t z);

  // Levels at or below zero cannot cover any ground (the heights are unsigned), so they are stored as 0.
  [[nodiscard]] inline std::uint16_t PackWaterLevel(
    const float level
  ) noexcept
  {
    if (!(level > -1000.0f)) {
      return kNoWaterRaw; // none, or NaN
    }
    const float units = std::floor(level / kWaterLevelUnit + 0.5f);
    return static_cast<std::uint16_t>(std::min(std::max(units, 0.0f), 65534.0f));
  }

  [[nodiscard]] inline float UnpackWaterLevel(
    const std::uint16_t raw
  ) noexcept
  {
    return raw == kNoWaterRaw ? kNoWaterLevel : static_cast<float>(raw) * kWaterLevelUnit;
  }

  // The blocks per side of the water map of a height field of `samples` vertices.
  [[nodiscard]] inline std::uint32_t WaterBlocksPerSide(
    const std::uint32_t samples
  ) noexcept
  {
    return samples > 1U ? (samples - 1U) >> 1U : 0U;
  }

  // The words of the level table, two blocks to a word (low half first), row by row: `blocksX * blocksZ` values.
  [[nodiscard]] inline std::vector<std::uint32_t> BuildWaterLevelWords(
    const void* const context,
    const WaterBlockLevelFunction levelOf,
    const std::uint32_t blocksX,
    const std::uint32_t blocksZ
  )
  {
    const std::size_t count = static_cast<std::size_t>(blocksX) * blocksZ;
    std::vector<std::uint32_t> words((count + 1U) / 2U, 0U);
    for (std::uint32_t bz = 0; bz < blocksZ; ++bz) {
      for (std::uint32_t bx = 0; bx < blocksX; ++bx) {
        const std::size_t index = static_cast<std::size_t>(bz) * blocksX + bx;
        const std::uint32_t raw =
          PackWaterLevel(levelOf(context, static_cast<std::int32_t>(bx * 2U), static_cast<std::int32_t>(bz * 2U)));
        words[index >> 1U] |= raw << ((index & 1U) * 16U);
      }
    }
    return words;
  }

  // What the field's shader does for a world position: the block (2 world units a side, clamped to the map), its
  // level. `levels` points at the first level word.
  [[nodiscard]] inline float WaterLevelAt(
    const std::uint32_t* const levels,
    const std::uint32_t blocksX,
    const std::uint32_t blocksZ,
    const float x,
    const float z
  ) noexcept
  {
    const auto block = [](const float v, const std::uint32_t count) {
      const float b = std::floor(v * 0.5f);
      return static_cast<std::uint32_t>(std::min(std::max(b, 0.0f), static_cast<float>(count) - 1.0f));
    };
    const std::size_t index = static_cast<std::size_t>(block(z, blocksZ)) * blocksX + block(x, blocksX);
    const std::uint32_t word = levels[index >> 1U];
    return UnpackWaterLevel(static_cast<std::uint16_t>((index & 1U) != 0U ? (word >> 16U) : (word & 0xFFFFU)));
  }

  // The share of the segment p -> q (heights `py`, `qy`) that lies under the water: the surface is the line between
  // the level over p and the level over q, so a light above a lake and a receiver on the sea bed beside it each see
  // their own water. Equal levels give the single-level result of before. The shader's WaterTransmit multiplies this
  // by the length of the segment and the absorption.
  [[nodiscard]] inline float WaterPathFraction(
    const float py,
    const float qy,
    const float levelP,
    const float levelQ
  ) noexcept
  {
    const float dp = py - levelP;
    const float dq = qy - levelQ;
    if (dp >= 0.0f && dq >= 0.0f) {
      return 0.0f;
    }
    if (dp < 0.0f && dq < 0.0f) {
      return 1.0f;
    }
    return dp < 0.0f ? (-dp) / (dq - dp) : (-dq) / (dp - dq);
  }
} // namespace moho::lights
