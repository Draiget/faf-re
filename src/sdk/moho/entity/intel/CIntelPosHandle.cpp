#include "CIntelPosHandle.h"

#include "moho/sim/CIntelGrid.h"

namespace
{
  [[nodiscard]] Wm3::Vec3f ReadWorldPos(const moho::EntityPositionWatchEntry& entry) noexcept
  {
    Wm3::Vec3f worldPos{};
    worldPos.x = entry.lastX;
    worldPos.y = entry.lastY;
    worldPos.z = entry.lastZ;
    return worldPos;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0076F180 (FUN_0076F180)
   *
   * What it does:
   * Adds this handle's circular coverage into the bound intel grid.
   */
  void CIntelPosHandle::AddViz()
  {
    if (isArmed == 0u || rangeWord == 0u || !mIntelGrid) {
      return;
    }

    mIntelGrid->AddCircle(ReadWorldPos(*this), rangeWord);
  }

  /**
   * Address: 0x0076F1B0 (FUN_0076F1B0)
   *
   * What it does:
   * Removes this handle's circular coverage from the bound intel grid
   * immediately.
   */
  void CIntelPosHandle::SubViz()
  {
    if (isArmed == 0u || rangeWord == 0u || !mIntelGrid) {
      return;
    }

    mIntelGrid->SubtractCircle(ReadWorldPos(*this), rangeWord);
  }
} // namespace moho
