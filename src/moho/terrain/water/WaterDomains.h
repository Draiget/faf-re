#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "ShoreField.h"

// The waters of a map with water bodies, as the wave simulation sees them (docs/WATER_SIMULATION.md, "Water bodies"):
// one domain per water (the sea is 0, a lake or a dry polder its body number), one table entry per block of 2 x 2
// height-field cells (a texel of the water map, the unit upstream's WaterOfBlock and the water meshes use, so the
// domain a cell simulates in is the water that is drawn there). Pure functions on plain values: the game and the
// headless lab (tools/watersimlab) run the same code.
namespace moho::water
{
  // Per block: the level of its water in raw height units with the margin of the land test already taken off
  // ((level - 0.1) * 128; kDryLevelRaw where there is no water) and the number of its domain, both as floats because
  // that is what the shader reads (the two segments after the shore fields in its buffer).
  struct DomainTable
  {
    std::uint32_t blocksX = 0U;
    std::uint32_t blocksZ = 0U;
    std::vector<float> levelRaw;
    std::vector<float> domain;
  };

  // `blockAt(bx, bz, level, body)`: the water level (world units, `noWater` for none) and the body of block (bx, bz).
  template <class BlockAt>
  DomainTable BuildDomainTable(
    const std::uint32_t blocksX,
    const std::uint32_t blocksZ,
    const float noWater,
    const float margin,
    BlockAt&& blockAt
  )
  {
    DomainTable table;
    table.blocksX = blocksX;
    table.blocksZ = blocksZ;
    table.levelRaw.resize(static_cast<std::size_t>(blocksX) * blocksZ);
    table.domain.resize(table.levelRaw.size());
    for (std::uint32_t bz = 0; bz < blocksZ; ++bz) {
      for (std::uint32_t bx = 0; bx < blocksX; ++bx) {
        float level = noWater;
        std::uint8_t body = 0U;
        blockAt(bx, bz, level, body);
        const std::size_t at = static_cast<std::size_t>(bz) * blocksX + bx;
        table.levelRaw[at] = level == noWater ? kDryLevelRaw : (level - margin) * 128.0f;
        table.domain[at] = static_cast<float>(body);
      }
    }
    return table;
  }

  // The block of the height sample (x, z): samples sit on the whole units, a block is two of them (the shader takes
  // the block of a cell's centre, floor(position / 2)).
  inline std::size_t BlockOfSample(
    const DomainTable& table,
    const std::uint32_t x,
    const std::uint32_t z
  )
  {
    const std::uint32_t bx = std::min(x >> 1U, table.blocksX - 1U);
    const std::uint32_t bz = std::min(z >> 1U, table.blocksZ - 1U);
    return static_cast<std::size_t>(bz) * table.blocksX + bx;
  }

  // The level of every domain in raw units (the first block that has the domain gives it): the input of
  // ComputeShoreDistanceDomains. Domains that no block has stay dry.
  inline std::vector<float> DomainLevels(
    const DomainTable& table
  )
  {
    std::vector<float> levels(256U, kDryLevelRaw);
    std::vector<std::uint8_t> seen(256U, 0U);
    for (std::size_t i = 0; i < table.domain.size(); ++i) {
      const std::size_t d = static_cast<std::size_t>(table.domain[i]);
      if (d < 256U && seen[d] == 0U) {
        seen[d] = 1U;
        levels[d] = table.levelRaw[i];
      }
    }
    return levels;
  }

  // The water the middle of the view looks at, on a map with several levels. The old rule (the point where the ray
  // meets the plane of the one sea level) has no answer here: the ray has to be followed down to the first surface
  // of any water. Marches from `pos` along `dir` in steps of `step` up to `maxT`; the first point below the water
  // surface of its place (levelAt(x, z, level) says where there is water) is the answer, refined by bisection. A ray
  // that meets the ground first, never goes down or meets no water gives false (the caller keeps the last centre).
  template <class GroundAt, class LevelAt>
  bool WaterWindowCentre(
    const float px,
    const float py,
    const float pz,
    const float dx,
    const float dy,
    const float dz,
    const float maxT,
    const float step,
    GroundAt&& groundAt,
    LevelAt&& levelAt,
    float& centreX,
    float& centreZ
  )
  {
    if (!(dy < -0.01f)) {
      return false;
    }
    const auto below = [&](const float t) {
      float level = 0.0f;
      return levelAt(px + dx * t, pz + dz * t, level) && py + dy * t < level;
    };
    float before = 0.0f;
    for (float t = 0.0f; t <= maxT; t += step) {
      if (below(t)) {
        float lo = before;
        float hi = t;
        for (int i = 0; i < 16; ++i) {
          const float mid = 0.5f * (lo + hi);
          (below(mid) ? hi : lo) = mid;
        }
        centreX = px + dx * hi;
        centreZ = pz + dz * hi;
        return true;
      }
      if (groundAt(px + dx * t, pz + dz * t) > py + dy * t) {
        return false; // the ground is in the way
      }
      before = t;
    }
    return false;
  }
} // namespace moho::water
