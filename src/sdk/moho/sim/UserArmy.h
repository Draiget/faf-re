#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/WeakObject.h"
#include "moho/misc/WeakPtr.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/SSTIArmyConstantData.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/WeakEntitySet.h"
#include "Wm3Vector3.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CWldSession;
  class UserEntity;
  class UserUnit;

  /**
   * `UserArmy` is the client-side army mirror. The shipped object embeds the
   * serialized army payload at offset 0 (`SSTIArmyConstantData` +0x00,
   * `SSTIArmyVariableData` +0x80) and appends the runtime-only registries the
   * UI needs.
   */
  class UserArmy : public SSTIArmyConstantData
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
     * Address: 0x008B1520 (FUN_008B1520)
     * Mangled: ??0UserArmy@Moho@@QAE@@Z
     *
     * IDA signature:
     * Moho::UserArmy *__stdcall Moho::UserArmy::UserArmy(
     *     Moho::UserArmy *this, Moho::CWldSession *session, Moho::SSTIArmyConstantData *a1);
     *
     * What it does:
     * Builds one client-side army mirror: constructs the serialized army
     * payload, binds the owning session, empties the avatar/engineer/factory
     * registries and copies the sim-supplied constant data over the payload.
     */
    UserArmy(CWldSession* session, const SSTIArmyConstantData& constantData);

    UserArmy(const UserArmy&) = delete;
    UserArmy& operator=(const UserArmy&) = delete;

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
     * Address: 0x005D5540 (FUN_005D5540, Moho::IArmy::IsEnemy)
     *
     * What it does:
     * Tests enemy-bitset membership for `armyIndex`.
     */
    [[nodiscard]] bool IsEnemy(std::uint32_t armyIndex) const;

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
    // 0x00..0x80 is the inherited `SSTIArmyConstantData` payload.
    SSTIArmyVariableData mVarDat; // 0x80

    /// Head of the intrusive chain of `WeakPtr<UserArmy>` nodes referencing us.
    /// `CUserSoundManager`'s listener-army hook links itself here.
    WeakObject mWeakRefs; // 0x1E0

    CWldSession* mSession; // 0x1E4

    /// Quick-select avatars: units whose blueprint `QuickSelectPriority` is
    /// positive register here from `UserUnit::UserUnit` (FUN_008B2300).
    msvc8::vector<WeakPtr<UserUnit>> mAvatars; // 0x1E8

    /// Idle-engineer registry, populated from `UserUnit::Tick` (FUN_008B2520)
    /// and read by `GetIdleEngineers` (FUN_008BCEF0).
    WeakEntitySetUserEntity mEngineers; // 0x1F8

    /// Idle-factory registry, populated from `UserUnit::Tick` (FUN_008B2590)
    /// and read by `GetIdleFactories` (FUN_008BD180).
    WeakEntitySetUserEntity mFactories; // 0x204
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
  // The constant-data payload is the base subobject; its own field offsets are
  // asserted in SSTIArmyConstantData.h.
  static_assert(sizeof(SSTIArmyConstantData) == 0x80, "UserArmy constant-data base must occupy 0x00..0x80");
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
  static_assert(offsetof(UserArmy, mWeakRefs) == 0x1E0, "UserArmy::mWeakRefs offset must be 0x1E0");
  static_assert(offsetof(UserArmy, mSession) == 0x1E4, "UserArmy::mSession offset must be 0x1E4");
  static_assert(offsetof(UserArmy, mAvatars) == 0x1E8, "UserArmy::mAvatars offset must be 0x1E8");
  static_assert(offsetof(UserArmy, mEngineers) == 0x1F8, "UserArmy::mEngineers offset must be 0x1F8");
  static_assert(offsetof(UserArmy, mFactories) == 0x204, "UserArmy::mFactories offset must be 0x204");
  static_assert(sizeof(WeakEntitySetUserEntity) == 0x0C, "WeakEntitySetUserEntity size must be 0x0C");
  static_assert(sizeof(UserArmy) == 0x210, "UserArmy size must be 0x210");
} // namespace moho
