#include "UserArmy.h"

#include "moho/console/CVarAccess.h"
#include "moho/math/GridPos.h"
#include "moho/sim/CWldSession.h"

namespace moho
{
  namespace
  {
    [[nodiscard]] constexpr bool HasReconMask(const UserArmy::EReconGridMask value, const UserArmy::EReconGridMask flag)
    {
      return (static_cast<std::uint8_t>(value) & static_cast<std::uint8_t>(flag)) != 0u;
    }
  } // namespace

  /**
   * Address: 0x008B14D0 (FUN_008B14D0, Moho::UserArmy::GetExploredReconGrid)
   */
  boost::shared_ptr<CIntelGrid> UserArmy::GetExploredReconGrid() const
  {
    return mExploredReconGrid;
  }

  /**
   * Address: 0x008B14F0 (FUN_008B14F0, Moho::UserArmy::GetFogReconGrid)
   */
  boost::shared_ptr<CIntelGrid> UserArmy::GetFogReconGrid() const
  {
    return mFogReconGrid;
  }

  /**
   * Address: 0x005BD630 (FUN_005BD630, Moho::IArmy::IsAlly)
   */
  bool UserArmy::IsAlly(const std::uint32_t armyIndex) const
  {
    if (armyIndex == 0xFFFFFFFFu) {
      return false;
    }
    if (!mAlliesSet.items_begin || !mAlliesSet.items_end) {
      return false;
    }
    return mAlliesSet.Contains(armyIndex);
  }

  /**
   * Address: 0x008B17F0 (FUN_008B17F0, Moho::UserArmy::CanSeeCell)
   */
  bool UserArmy::CanSeeCell(const std::int32_t x, const std::int32_t z, const EReconGridMask gridMask) const
  {
    CIntelGrid* const exploredGrid = mExploredReconGrid.get();
    if (!exploredGrid) {
      return true;
    }
    if (!console::RenderFogOfWarEnabled()) {
      return true;
    }

    const bool useFog = HasReconMask(gridMask, EReconGridMask::Fog);
    const bool useExplored = HasReconMask(gridMask, EReconGridMask::Explored);

    if (useExplored && exploredGrid->IsVisible(x, z)) {
      return true;
    }
    if (useFog && mFogReconGrid && mFogReconGrid->IsVisible(x, z)) {
      return true;
    }

    const msvc8::vector<UserArmy*>& armies = mSession->userArmies;
    for (std::size_t i = 0; i < armies.size(); ++i) {
      UserArmy* const ally = armies[i];
      if (ally == this || !ally->IsAlly(mArmyIndex)) {
        continue;
      }

      if (useExplored) {
        const boost::shared_ptr<CIntelGrid> allyExploredGrid = ally->GetExploredReconGrid();
        if (!allyExploredGrid || allyExploredGrid->IsVisible(x, z)) {
          return true;
        }
      }

      if (useFog) {
        const boost::shared_ptr<CIntelGrid> allyFogGrid = ally->GetFogReconGrid();
        if (!allyFogGrid || allyFogGrid->IsVisible(x, z)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Address: 0x008B22B0 (FUN_008B22B0, Moho::UserArmy::CanSeePoint)
   */
  bool UserArmy::CanSeePoint(const Wm3::Vec3f& worldPos, const EReconGridMask gridMask) const
  {
    CIntelGrid* const exploredGrid = mExploredReconGrid.get();
    if (!exploredGrid) {
      return true;
    }
    if (!console::RenderFogOfWarEnabled()) {
      return true;
    }

    Wm3::Vec3f cellPos = worldPos;
    const GridPos gridCell(&cellPos, exploredGrid->mGridSize);
    return CanSeeCell(gridCell.x, gridCell.z, gridMask);
  }
} // namespace moho
