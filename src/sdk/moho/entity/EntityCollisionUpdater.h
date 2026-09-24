#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/collision/CColPrimitiveBase.h"

namespace moho
{
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
