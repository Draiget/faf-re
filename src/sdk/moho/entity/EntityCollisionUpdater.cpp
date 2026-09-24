#include "EntityCollisionUpdater.h"

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x007237E0 (FUN_007237E0, func_CopyCollisionResultArr2)
   *
   * What it does:
   * Copies `CollisionResult` lanes backward from `[sourceBegin, sourceEnd)`
   * into destination range ending at `outEnd`.
   */
  CollisionResult* CopyCollisionResultsBackward(
    CollisionResult* const outEnd,
    const CollisionResult* const sourceEnd,
    const CollisionResult* const sourceBegin
  ) noexcept
  {
    CollisionResult* destinationCursor = outEnd;
    const CollisionResult* sourceCursor = sourceEnd;
    while (sourceCursor != sourceBegin) {
      --sourceCursor;
      --destinationCursor;
      *destinationCursor = *sourceCursor;
    }
    return destinationCursor;
  }

  /**
   * Address: 0x00723770 (FUN_00723770, func_CopyCollisionResultArr3)
   *
   * What it does:
   * Binary-twin entry point for backward `CollisionResult` range copies.
   */
  CollisionResult* CopyCollisionResultsBackwardAlt(
    CollisionResult* const outEnd,
    const CollisionResult* const sourceEnd,
    const CollisionResult* const sourceBegin
  ) noexcept
  {
    return CopyCollisionResultsBackward(outEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00723610 (FUN_00723610)
   *
   * What it does:
   * Register/stack adapter that forwards one backward range copy request to
   * `CopyCollisionResultsBackwardAlt`.
   */
  [[maybe_unused]] CollisionResult* CopyCollisionResultsBackwardAltAdapter(
    CollisionResult* const sourceBegin,
    CollisionResult* const sourceEnd,
    CollisionResult* const destinationEnd
  ) noexcept
  {
    return CopyCollisionResultsBackwardAlt(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00723640 (FUN_00723640)
   *
   * What it does:
   * Register/stack adapter that forwards one backward range copy request to
   * `CopyCollisionResultsBackward`.
   */
  [[maybe_unused]] CollisionResult* CopyCollisionResultsBackwardAdapter(
    CollisionResult* const sourceBegin,
    CollisionResult* const sourceEnd,
    CollisionResult* const destinationEnd
  ) noexcept
  {
    return CopyCollisionResultsBackward(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00723410 (FUN_00723410, func_CopyCollisionResultArr1)
   *
   * What it does:
   * Copies `CollisionResult` lanes forward from `[sourceBegin, sourceEnd)` into
   * destination range starting at `outBegin`.
   */
  CollisionResult* CopyCollisionResultsForward(
    CollisionResult* const outBegin,
    const CollisionResult* const sourceBegin,
    const CollisionResult* const sourceEnd
  ) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(outBegin);
    const std::uintptr_t stride = static_cast<std::uintptr_t>(sizeof(CollisionResult));

    const CollisionResult* sourceCursor = sourceBegin;
    while (sourceCursor != sourceEnd) {
      if (destinationAddress != 0u) {
        *reinterpret_cast<CollisionResult*>(destinationAddress) = *sourceCursor;
      }

      destinationAddress += stride;
      ++sourceCursor;
    }

    return reinterpret_cast<CollisionResult*>(destinationAddress);
  }

  /**
   * Address: 0x00723090 (FUN_00723090, sub_723090)
   *
   * What it does:
   * Inserts one `CollisionResult` range `[sourceBegin, sourceEnd)` before
   * `insertBefore` in the active `fastvector_n` lane, growing storage when
   * required, and returns the rebased insertion pointer.
   */
  CollisionResult* InsertCollisionResultRange(
    gpg::core::FastVectorN<CollisionResult, 10>& outCollisions,
    CollisionResult* insertBefore,
    const CollisionResult* const sourceBegin,
    const CollisionResult* const sourceEnd
  ) noexcept
  {
    if (sourceBegin == sourceEnd) {
      return insertBefore;
    }

    CollisionResult* const begin = outCollisions.start_;
    CollisionResult* const end = outCollisions.end_;

    if (insertBefore == nullptr || insertBefore < begin) {
      insertBefore = begin;
    } else if (insertBefore > end) {
      insertBefore = end;
    }

    const std::size_t insertionOffset = static_cast<std::size_t>(insertBefore - begin);
    outCollisions.InsertAt(insertBefore, sourceBegin, sourceEnd);
    return outCollisions.start_ + insertionOffset;
  }
} // namespace moho
