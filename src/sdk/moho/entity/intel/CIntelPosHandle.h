#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/entity/EntityPositionWatchEntry.h"

namespace moho
{
  class CIntelGrid;

  /**
   * Recovered concrete viz handle used by Entity intel proximity updates.
   *
   * Constructor/layout evidence:
   * - FUN_0076D810 writes +0x1C/+0x20 and sets size-class to 0x24 (FUN_0076F0A0).
   */
  class CIntelPosHandle : public EntityPositionWatchEntry
  {
  public:
    /**
     * Address: 0x0076F180 (FUN_0076F180)
     *
     * What it does:
     * Adds this handle's circular coverage into the bound intel grid.
     */
    void AddViz() override;

    /**
     * Address: 0x0076F1B0 (FUN_0076F1B0)
     *
     * What it does:
     * Removes this handle's circular coverage from the bound intel grid
     * immediately.
     */
    void SubViz() override;

    CIntelGrid* mIntelGrid; // +0x1C
    void* mIntelGridOwner;  // +0x20
  };

#if defined(_M_IX86)
  static_assert(sizeof(CIntelPosHandle) == 0x24, "CIntelPosHandle size must be 0x24");
  static_assert(offsetof(CIntelPosHandle, mIntelGrid) == 0x1C, "CIntelPosHandle::mIntelGrid offset must be 0x1C");
  static_assert(
    offsetof(CIntelPosHandle, mIntelGridOwner) == 0x20, "CIntelPosHandle::mIntelGridOwner offset must be 0x20"
  );
#endif
} // namespace moho
