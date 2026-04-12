#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "Wm3Vector3.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CWldSession;

  class UserArmy
  {
  public:
    enum class EReconGridMask : std::uint8_t
    {
      None = 0x00,
      Explored = 0x01,
      Fog = 0x02,
      Both = 0x03,
    };

    /**
     * Address: 0x008B14D0 (FUN_008B14D0, Moho::UserArmy::GetExploredReconGrid)
     *
     * What it does:
     * Returns a retained shared-pointer view of the explored recon grid.
     */
    [[nodiscard]] boost::shared_ptr<CIntelGrid> GetExploredReconGrid() const;

    /**
     * Address: 0x008B14F0 (FUN_008B14F0, Moho::UserArmy::GetFogReconGrid)
     *
     * What it does:
     * Returns a retained shared-pointer view of the fog recon grid.
     */
    [[nodiscard]] boost::shared_ptr<CIntelGrid> GetFogReconGrid() const;

    /**
     * Address: 0x005BD630 (FUN_005BD630, Moho::IArmy::IsAlly)
     *
     * What it does:
     * Tests ally-bitset membership for `armyIndex`.
     */
    [[nodiscard]] bool IsAlly(std::uint32_t armyIndex) const;

    /**
     * Address: 0x008B17F0 (FUN_008B17F0, Moho::UserArmy::CanSeeCell)
     *
     * What it does:
     * Resolves visibility for a grid cell using own and allied recon grids.
     */
    [[nodiscard]] bool CanSeeCell(std::int32_t x, std::int32_t z, EReconGridMask gridMask) const;

    /**
     * Address: 0x008B22B0 (FUN_008B22B0, Moho::UserArmy::CanSeePoint)
     *
     * What it does:
     * Converts world position to grid cell and delegates to `CanSeeCell`.
     */
    [[nodiscard]] bool CanSeePoint(const Wm3::Vec3f& worldPos, EReconGridMask gridMask) const;

  public:
    std::uint32_t mArmyIndex;  // 0x00
    msvc8::string mArmyName;   // 0x04
    msvc8::string mPlayerName; // 0x20
    std::uint8_t mIsCivilian;  // 0x3C
    std::uint8_t mConstantDataPad_003D_0040[0x03]{};
    boost::shared_ptr<CIntelGrid> mExploredReconGrid; // 0x40
    boost::shared_ptr<CIntelGrid> mFogReconGrid;      // 0x48
    boost::shared_ptr<CIntelGrid> mWaterReconGrid;    // 0x50
    boost::shared_ptr<CIntelGrid> mRadarReconGrid;    // 0x58
    boost::shared_ptr<CIntelGrid> mSonarReconGrid;    // 0x60
    boost::shared_ptr<CIntelGrid> mOmniReconGrid;     // 0x68
    boost::shared_ptr<CIntelGrid> mRciReconGrid;      // 0x70
    boost::shared_ptr<CIntelGrid> mSciReconGrid;      // 0x78
    SSTIArmyVariableData mVarDat; // 0x80
    std::uint32_t mVariableDataWord_01E0; // 0x1E0 (ctor writes zero)
    CWldSession* mSession;                // 0x1E4
    // Runtime-only tail members (constructor/destructor touch +0x1EC..+0x20C).
    std::uint8_t mRuntimeTail_01E8_0210[0x28]{};
  };

  /**
   * Address: 0x008B9920 (FUN_008B9920, Moho::ARMY_FromLuaState)
   * Mangled: ?ARMY_FromLuaState@Moho@@YAPAVUserArmy@1@PAVLuaState@LuaPlus@@VLuaObject@4@@Z
   *
   * What it does:
   * Resolves one Lua user-army selector (1-based numeric index or army name)
   * to one `UserArmy*` in the active world session.
   */
  [[nodiscard]] UserArmy* USER_ResolveArmyFromLuaState(LuaPlus::LuaState* state, const LuaPlus::LuaObject& armyObject);

  static_assert(sizeof(boost::shared_ptr<CIntelGrid>) == 0x08, "shared_ptr<CIntelGrid> size must be 0x08");
  static_assert(offsetof(UserArmy, mArmyName) == 0x04, "UserArmy::mArmyName offset must be 0x04");
  static_assert(offsetof(UserArmy, mPlayerName) == 0x20, "UserArmy::mPlayerName offset must be 0x20");
  static_assert(offsetof(UserArmy, mIsCivilian) == 0x3C, "UserArmy::mIsCivilian offset must be 0x3C");
  static_assert(offsetof(UserArmy, mExploredReconGrid) == 0x40, "UserArmy::mExploredReconGrid offset must be 0x40");
  static_assert(offsetof(UserArmy, mFogReconGrid) == 0x48, "UserArmy::mFogReconGrid offset must be 0x48");
  static_assert(offsetof(UserArmy, mWaterReconGrid) == 0x50, "UserArmy::mWaterReconGrid offset must be 0x50");
  static_assert(offsetof(UserArmy, mRadarReconGrid) == 0x58, "UserArmy::mRadarReconGrid offset must be 0x58");
  static_assert(offsetof(UserArmy, mSonarReconGrid) == 0x60, "UserArmy::mSonarReconGrid offset must be 0x60");
  static_assert(offsetof(UserArmy, mOmniReconGrid) == 0x68, "UserArmy::mOmniReconGrid offset must be 0x68");
  static_assert(offsetof(UserArmy, mRciReconGrid) == 0x70, "UserArmy::mRciReconGrid offset must be 0x70");
  static_assert(offsetof(UserArmy, mSciReconGrid) == 0x78, "UserArmy::mSciReconGrid offset must be 0x78");
  static_assert(offsetof(UserArmy, mVarDat) == 0x80, "UserArmy::mVarDat offset must be 0x80");
  static_assert(
    offsetof(UserArmy, mVarDat) + offsetof(SSTIArmyVariableData, mAllies) == 0xE0,
    "UserArmy::mVarDat.mAllies offset must be 0xE0"
  );
  static_assert(
    offsetof(UserArmy, mVarDat) + offsetof(SSTIArmyVariableData, mAllies) + offsetof(Set, meta) == 0xE4,
    "UserArmy::mVarDat.mAllies.meta offset must be 0xE4"
  );
  static_assert(
    offsetof(UserArmy, mVarDat) + offsetof(SSTIArmyVariableData, mAllies) + offsetof(Set, items_begin) == 0xE8,
    "UserArmy::mVarDat.mAllies.items_begin offset must be 0xE8"
  );
  static_assert(
    offsetof(UserArmy, mVarDat) + offsetof(SSTIArmyVariableData, mAllies) + offsetof(Set, items_end) == 0xEC,
    "UserArmy::mVarDat.mAllies.items_end offset must be 0xEC"
  );
  static_assert(
    offsetof(UserArmy, mVariableDataWord_01E0) == 0x1E0, "UserArmy::mVariableDataWord_01E0 offset must be 0x1E0"
  );
  static_assert(offsetof(UserArmy, mSession) == 0x1E4, "UserArmy::mSession offset must be 0x1E4");
  static_assert(sizeof(UserArmy) == 0x210, "UserArmy size must be 0x210");
} // namespace moho
