#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/collision/CColPrimitiveBase.h"

namespace moho
{
  /**
   * Quantized collision-cell rectangle (one cell = 4 world units). Layout matches
   * `Moho::CollisionDBRect` (COGrid.h) exactly; kept as a distinct name for the
   * `BuildCollisionCellRectFromBounds` return, and reinterpret-bridged where a
   * `CollisionDBRect` is required.
   */
  struct CollisionCellRect
  {
    std::uint16_t startX;
    std::uint16_t startZ;
    std::uint16_t width;
    std::uint16_t height;
  };
  static_assert(sizeof(CollisionCellRect) == 0x08, "CollisionCellRect size must be 0x08");

  namespace detail
  {
    [[nodiscard]] inline int FloorToInt(const float value) noexcept
    {
      return static_cast<int>(std::floor(static_cast<double>(value)));
    }

    [[nodiscard]] inline int CeilToInt(const float value) noexcept
    {
      return static_cast<int>(std::ceil(static_cast<double>(value)));
    }

    [[nodiscard]] inline std::uint16_t ClampCellStartToU16(const int value) noexcept
    {
      if (value <= 0) {
        return 0;
      }
      if (value >= 0xFFFF) {
        return 0xFFFFu;
      }
      return static_cast<std::uint16_t>(value);
    }

    [[nodiscard]] inline std::uint16_t ClampCellExtentToU16(const int extentCandidate, const std::uint16_t startCell) noexcept
    {
      const int maxExtent = 0xFFFF - static_cast<int>(startCell);
      int extent = extentCandidate;
      if (extent >= maxExtent) {
        extent = maxExtent;
      }
      if (extent < 0) {
        extent = 0;
      }
      return static_cast<std::uint16_t>(extent);
    }
  } // namespace detail

  /**
   * Address: 0x004FCBE0 (FUN_004FCBE0)
   *
   * What it does:
   * Converts world-space AABB bounds `{min,max}` into a quantized collision-cell
   * rectangle `{startX,startZ,width,height}` (one cell = 4 world units): floors
   * the min corner and ceils the max corner (both `>> 2`), clamping the start
   * corner into `[0, 0xFFFF]` and the width/height to at least the remaining
   * span. Shared leaf used by `func_EntitiesAroundPoint` (COGrid.cpp) and the
   * entity collision-updater rebuild path (Entity.cpp).
   */
  [[nodiscard]] inline CollisionCellRect
  BuildCollisionCellRectFromBounds(const EntityCollisionBoundsView& bounds) noexcept
  {
    const int minCellX = detail::FloorToInt(bounds.minX) >> 2;
    const int minCellZ = detail::FloorToInt(bounds.minZ) >> 2;
    const int maxCellX = (detail::CeilToInt(bounds.maxX) + 3) >> 2;
    const int maxCellZ = (detail::CeilToInt(bounds.maxZ) + 3) >> 2;

    CollisionCellRect rect{};
    rect.startX = detail::ClampCellStartToU16(minCellX);
    rect.startZ = detail::ClampCellStartToU16(minCellZ);
    rect.width = detail::ClampCellExtentToU16(maxCellX - static_cast<int>(rect.startX), rect.startX);
    rect.height = detail::ClampCellExtentToU16(maxCellZ - static_cast<int>(rect.startZ), rect.startZ);
    return rect;
  }

  /**
   * Address: 0x007237E0 (FUN_007237E0, func_CopyCollisionResultArr2)
   *
   * What it does:
   * Copies one `CollisionResult` range backward from `[sourceBegin, sourceEnd)`
   * into output ending at `outEnd`; returns the destination begin pointer.
   */
  [[nodiscard]] CollisionResult* CopyCollisionResultsBackward(
    CollisionResult* outEnd,
    const CollisionResult* sourceEnd,
    const CollisionResult* sourceBegin
  ) noexcept;

  /**
   * Address: 0x00723770 (FUN_00723770, func_CopyCollisionResultArr3)
   *
   * What it does:
   * Binary twin of `CopyCollisionResultsBackward`; copies one
   * `CollisionResult` range backward from `[sourceBegin, sourceEnd)` into
   * output ending at `outEnd` and returns the destination begin pointer.
   */
  [[nodiscard]] CollisionResult* CopyCollisionResultsBackwardAlt(
    CollisionResult* outEnd,
    const CollisionResult* sourceEnd,
    const CollisionResult* sourceBegin
  ) noexcept;

  /**
   * Address: 0x00723410 (FUN_00723410, func_CopyCollisionResultArr1)
   *
   * What it does:
   * Copies one `CollisionResult` range forward from `[sourceBegin, sourceEnd)`
   * into output beginning at `outBegin`; returns the destination end pointer.
   *
   * Binary note:
   * The original helper increments the destination cursor even when `outBegin`
   * is null (used as a size/cursor lane by callers). The implementation keeps
   * that behavior.
   */
  [[nodiscard]] CollisionResult* CopyCollisionResultsForward(
    CollisionResult* outBegin,
    const CollisionResult* sourceBegin,
    const CollisionResult* sourceEnd
  ) noexcept;

  /**
   * Address: 0x00723090 (FUN_00723090, sub_723090)
   *
   * What it does:
   * Inserts one `CollisionResult` range `[sourceBegin, sourceEnd)` before
   * `insertBefore` in `outCollisions`, growing storage when required, and
   * returns the rebased insertion pointer in the active storage lane.
   */
  [[nodiscard]] CollisionResult* InsertCollisionResultRange(
    gpg::core::FastVectorN<CollisionResult, 10>& outCollisions,
    CollisionResult* insertBefore,
    const CollisionResult* sourceBegin,
    const CollisionResult* sourceEnd
  ) noexcept;
} // namespace moho
