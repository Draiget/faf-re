#include "UserArmy.h"

#include <cstring>
#include <string>

#include "lua/LuaObject.h"
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

    constexpr const char* kInvalidArmyMessage = "Invalid army %d";
    constexpr const char* kInvalidArmyOneBasedMessage = "Invalid army %d. (Use a 1-based index)";
    constexpr const char* kUnknownArmyMessage = "Unknown army: %s";
    constexpr const char* kUnexpectedArmyTypeMessage = "Unexpected type for army object";
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

    const Set& allies = mVarDat.mAllies;
    if (!allies.items_begin || !allies.items_end) {
      return false;
    }

    return allies.Contains(armyIndex);
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

  /**
   * Address: 0x008B9920 (FUN_008B9920, Moho::ARMY_FromLuaState)
   * Mangled: ?ARMY_FromLuaState@Moho@@YAPAVUserArmy@1@PAVLuaState@LuaPlus@@VLuaObject@4@@Z
   *
   * What it does:
   * Resolves one Lua user-army selector (1-based numeric index or army name)
   * to one `UserArmy*` in the active world session.
   */
  UserArmy* USER_ResolveArmyFromLuaState(LuaPlus::LuaState* const state, const LuaPlus::LuaObject& armyObject)
  {
    CWldSession* const session = WLD_GetActiveSession();
    if (!session) {
      return nullptr;
    }

    const msvc8::vector<UserArmy*>& userArmies = session->userArmies;
    const int armyCount = static_cast<int>(userArmies.size());
    UserArmy* resolved = nullptr;

    if (armyObject.IsNumber()) {
      const int requestedArmy = armyObject.GetInteger();
      const int zeroBasedArmy = requestedArmy - 1;
      if (zeroBasedArmy < 0) {
        LuaPlus::LuaState::Error(state, kInvalidArmyOneBasedMessage, requestedArmy);
      } else if (zeroBasedArmy >= armyCount || (resolved = userArmies[static_cast<std::size_t>(zeroBasedArmy)]) == nullptr) {
        LuaPlus::LuaState::Error(state, kInvalidArmyMessage, zeroBasedArmy);
      }
      return resolved;
    }

    if (armyObject.IsString()) {
      const char* const requestedNameCStr = armyObject.GetString();
      const std::string requestedName = requestedNameCStr ? requestedNameCStr : "";

      for (int index = 0; index < armyCount; ++index) {
        UserArmy* const candidate = userArmies[static_cast<std::size_t>(index)];
        const char* const candidateName = candidate ? candidate->mArmyName.c_str() : nullptr;
        if (candidateName != nullptr && _stricmp(candidateName, requestedName.c_str()) == 0) {
          resolved = candidate;
          break;
        }
      }

      if (!resolved) {
        LuaPlus::LuaState::Error(state, kUnknownArmyMessage, requestedName.c_str());
      }
      return resolved;
    }

    LuaPlus::LuaState::Error(state, kUnexpectedArmyTypeMessage);
    return nullptr;
  }
} // namespace moho
