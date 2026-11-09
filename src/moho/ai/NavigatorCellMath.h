#pragma once

#include <cmath>
#include <cstdint>
#include <cstdlib>

#include "moho/sim/SOCellPos.h"

namespace moho
{
  /**
   * Engine addition (dedicated-server plan WPL.23): the path navigator's cell
   * arithmetic, moved unchanged out of CAiPathNavigator.cpp's anonymous
   * namespace so tests/sim_math can check it bit for bit.
   *
   * Every navigator helper reads a path cell's words with `movzx` (0x005AD370,
   * 0x005AD3B0, 0x005AE170, 0x005AF360, 0x005AEE0E...); only IsCellInGoal
   * (0x005AD800) uses `movsx`. A cell just off the top/left map edge is
   * therefore 65535, not -1, in every distance, delta and projection there.
   */
  [[nodiscard]] constexpr std::int32_t UnsignedCellCoord(const std::int16_t coord) noexcept
  {
    return static_cast<std::int32_t>(static_cast<std::uint16_t>(coord));
  }

  /**
   * Address: 0x005AD370 (FUN_005AD370)
   *
   * What it does:
   * Computes Euclidean cell-space distance between two packed path cells.
   *
   * 0x005AD379..0x005AD38A load both cells with `movzx`: a target cell at
   * z = -1 (a formation slot just off the map edge) is 65535 cells away, not
   * one. Sign-extending made such a target look near, so the shortcut probe in
   * UpdateCurrentPosition tested the off-map cell itself instead of a
   * projection, failed, forced a repath and skipped the formation-leader sync
   * (replay 26954643 beat 19560: SetTargetPoint(0) instead of RequestPath(0)).
   */
  [[nodiscard]] inline float CellDistance(const SOCellPos a, const SOCellPos b) noexcept
  {
    const float dx = static_cast<float>(UnsignedCellCoord(a.x) - UnsignedCellCoord(b.x));
    const float dz = static_cast<float>(UnsignedCellCoord(a.z) - UnsignedCellCoord(b.z));
    return std::sqrt((dx * dx) + (dz * dz));
  }

  // 0x005AD3B0 (and its inlined copies) take the words with `movzx` too.
  [[nodiscard]] inline std::int32_t ManhattanDistance(const SOCellPos a, const SOCellPos b) noexcept
  {
    const std::int32_t dx = std::abs(UnsignedCellCoord(a.x) - UnsignedCellCoord(b.x));
    const std::int32_t dz = std::abs(UnsignedCellCoord(a.z) - UnsignedCellCoord(b.z));
    return dx + dz;
  }
} // namespace moho
