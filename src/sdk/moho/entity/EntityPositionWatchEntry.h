#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  /**
   * Shared prefix used by proximity/intel watch handles stored by Entity.
   *
   * Prefix layout evidence:
   * - FUN_0076F1E0/FUN_0076E4C0 read/write:
   *   +0x04/+0x08/+0x0C position, +0x10 range, +0x14 lastTick, +0x18 armed-flag.
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

    float lastX;
    float lastY;
    float lastZ;
    std::uint32_t rangeWord;
    std::int32_t lastTick;
    std::uint8_t isArmed;
    std::uint8_t pad_19[3];
  };

#if defined(_M_IX86)
  static_assert(sizeof(EntityPositionWatchEntry) == 0x1C, "EntityPositionWatchEntry size must be 0x1C");
  static_assert(
    offsetof(EntityPositionWatchEntry, lastX) == 0x04, "EntityPositionWatchEntry::lastX offset must be 0x04"
  );
  static_assert(
    offsetof(EntityPositionWatchEntry, rangeWord) == 0x10, "EntityPositionWatchEntry::rangeWord offset must be 0x10"
  );
  static_assert(
    offsetof(EntityPositionWatchEntry, lastTick) == 0x14, "EntityPositionWatchEntry::lastTick offset must be 0x14"
  );
  static_assert(
    offsetof(EntityPositionWatchEntry, isArmed) == 0x18, "EntityPositionWatchEntry::isArmed offset must be 0x18"
  );
#endif
} // namespace moho
