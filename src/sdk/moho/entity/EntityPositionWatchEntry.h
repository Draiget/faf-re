#pragma once

#include <cstddef>
#include <cstdint>

#include "wm3/Vector3.h"

namespace moho
{
  /**
   * Shared prefix used by proximity/intel watch handles stored by Entity.
   *
   * Prefix layout evidence:
   * - FUN_0076F1E0/FUN_0076E4C0 read/write:
   *   +0x04/+0x08/+0x0C position, +0x10 radius, +0x14 lastTick, +0x18 enabled-flag.
   *
   * Concrete RTTI-backed implementations:
   * - CIntelPosHandle (size 0x24)
   * - CIntelCounterHandle (size 0x30)
   */
  class EntityPositionWatchEntry
  {
  public:
    /**
     * VTable slot 0.
     *
     * Concrete bodies:
     * - Address: 0x0076F180 (FUN_0076F180, Moho::CIntelPosHandle::AddViz)
     * - Address: 0x0076F5D0 (FUN_0076F5D0, Moho::CIntelCounterHandle::AddViz)
     */
    virtual void AddViz() = 0;

    /**
     * VTable slot 1.
     *
     * Concrete bodies:
     * - Address: 0x0076F1B0 (FUN_0076F1B0, Moho::CIntelPosHandle::SubViz)
     * - Address: 0x0076F720 (FUN_0076F720, Moho::CIntelCounterHandle::SubViz)
     */
    virtual void SubViz() = 0;

    /**
     * VTable slot 2.
     *
     * Concrete bodies:
     * - Address: 0x0076D9D0 (FUN_0076D9D0, Moho::CIntelPosHandle::dtr)
     * - Address: 0x0076DAC0 (FUN_0076DAC0, Moho::CIntelCounterHandle::dtr)
     */
    virtual void Destroy(int shouldDelete) = 0;

    Wm3::Vec3f mLastPos;
    std::uint32_t mRadius;
    std::int32_t mLastTickUpdated;
    std::uint8_t mEnabled;
    std::uint8_t mPad19[3];
  };

#if defined(_M_IX86)
  static_assert(sizeof(EntityPositionWatchEntry) == 0x1C, "EntityPositionWatchEntry size must be 0x1C");
  static_assert(
    offsetof(EntityPositionWatchEntry, mLastPos) == 0x04, "EntityPositionWatchEntry::mLastPos offset must be 0x04"
  );
  static_assert(
    offsetof(EntityPositionWatchEntry, mRadius) == 0x10, "EntityPositionWatchEntry::mRadius offset must be 0x10"
  );
  static_assert(
    offsetof(EntityPositionWatchEntry, mLastTickUpdated) == 0x14,
    "EntityPositionWatchEntry::mLastTickUpdated offset must be 0x14"
  );
  static_assert(
    offsetof(EntityPositionWatchEntry, mEnabled) == 0x18, "EntityPositionWatchEntry::mEnabled offset must be 0x18"
  );
#endif
} // namespace moho
