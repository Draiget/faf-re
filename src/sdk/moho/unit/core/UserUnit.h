// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "legacy/containers/Set.h"
#include "legacy/containers/String.h"
#include "moho/lua/CScrLuaBinderFwd.h"

#include <cstddef>
#include <cstdint>

struct lua_State;

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class SSTIEntityVariableData;
  class UserEntity;
  struct UserUnitManager;
  class UserUnitWeapon;
  class CWldSession;
  struct RUnitBlueprint;
  struct SCoordsVec2;
} // namespace moho

namespace moho
{
  /**
   * VFTABLE: 0x00E4D93C
   * COL:  0x00E9F48C
   */
  class UserUnit
  {
  public:
    /**
     * Address: 0x008BF990
     * Slot: 0
     * Demangled: DestroyUserUnit
     *
     * std::uint8_t deleteFlags
     *
     * IDA signature:
     * void* __thiscall sub_8BF990(void* this, char deleteFlags);
     */
    virtual UserUnit* DestroyUserUnit(std::uint8_t deleteFlags);

    /**
     * Address: 0x008C0A30
     * Slot: 1
     * Demangled: moho::UserUnit::Tick
     *
     * What it does:
     * Per-beat update hook for UI unit state.
     */
    virtual void Tick(std::int32_t seqNo);

    /**
     * Address: 0x008BF120
     * Slot: 2
     * Demangled: moho::UserUnit::IsUserUnit1
     *
     * What it does:
     * Returns this object as the const UserUnit identity view.
     */
    virtual UserUnit const* IsUserUnit1() const;

    /**
     * Address: 0x008BF110
     * Slot: 3
     * Demangled: moho::UserUnit::IsUserUnit2
     *
     * What it does:
     * Returns this object as the mutable UserUnit identity view.
     */
    virtual UserUnit* IsUserUnit2();

    /**
     * Address: 0x008BF170
     * Slot: 4
     * Demangled: moho::UserUnit::GetUnitformScale
     *
     * What it does:
     * Reads uniform render scale from the unit blueprint through the embedded IUnit bridge.
     */
    virtual float GetUnitformScale() const;

    /**
     * Address: 0x008BF150
     * Slot: 5
     * Demangled: moho::UserUnit::GetCommandQueue1
     *
     * What it does:
     * Returns the current user command-queue handle (mutable view slot).
     */
    virtual std::int32_t GetCommandQueue1();

    /**
     * Address: 0x008BF130
     * Slot: 6
     * Demangled: moho::UserUnit::GetCommandQueue2
     *
     * What it does:
     * Returns the current user command-queue handle (const view slot).
     */
    virtual std::int32_t GetCommandQueue2() const;

    /**
     * Address: 0x008BF160
     * Slot: 7
     * Demangled: moho::UserUnit::GetFactoryCommandQueue1
     *
     * What it does:
     * Returns the current factory command-queue handle (mutable view slot).
     */
    virtual std::int32_t GetFactoryCommandQueue1();

    /**
     * Address: 0x008BF140
     * Slot: 8
     * Demangled: moho::UserUnit::GetFactoryCommandQueue2
     *
     * What it does:
     * Returns the current factory command-queue handle (const view slot).
     */
    virtual std::int32_t GetFactoryCommandQueue2() const;

    /**
     * Address: 0x008B8EB0
     * Slot: 9
     * Demangled: public: virtual void __thiscall moho::UserEntity::UpdateEntityData(struct moho::SSTIEntityVariableData
     * const near &)
     */
    virtual void UpdateEntityData(moho::SSTIEntityVariableData const&);

    /**
     * Address: 0x008C09B0
     * Slot: 10
     * Demangled: moho::UserUnit::UpdateVisibility
     */
    virtual void UpdateVisibility();

    /**
     * Address: 0x008B8530
     * Slot: 11
     * Demangled: public: virtual bool __thiscall moho::UserEntity::RequiresUIRefresh(void)const
     *
     * What it does:
     * Returns replicated UI-dirty state from the UserEntity variable-data block.
     */
    virtual bool RequiresUIRefresh() const;

    /**
     * Address: 0x008C0500
     * Slot: 12
     * Demangled: moho::UserUnit::Select
     *
     * What it does:
     * Returns whether this unit should be selectable in user UI state.
     */
    virtual bool Select();

    /**
     * Address: 0x008BEFB0
     * Slot: 13
     * Demangled: moho::UserUnit::IsBeingBuilt
     *
     * What it does:
     * Returns replicated "being built" state from the UserEntity variable-data block.
     */
    virtual bool IsBeingBuilt() const;

    /**
     * Address: 0x008C1350
     * Slot: 14
     * Demangled: moho::UserUnit::NotifyFocusArmyUnitDamaged
     *
     * What it does:
     * Imports the UI game-main module and calls
     * `OnFocusArmyUnitDamaged(thisLuaObject)`.
     */
    virtual void NotifyFocusArmyUnitDamaged();

    /**
     * Address: 0x008C00E0
     * Slot: 15
     * Demangled: moho::UserUnit::CreateMeshInstance
     *
     * What it does:
     * Creates one unit mesh-instance with team-color setup and pose reuse from
     * unit variable-data shared-pose lanes.
     */
    virtual void CreateMeshInstance();

    /**
     * Address: 0x008C04D0
     * Slot: 16
     * Demangled: protected: virtual void __thiscall moho::UserEntity::DestroyMeshInstance(void)
     */
    virtual void DestroyMeshInstance();

    /**
     * Address: 0x008BFC50
     * Slot: 17
     * Demangled: moho::UserUnit::FindWeaponBy
     *
     * What it does:
     * Aggregates min/max ranges across weapon runtime entries that match
     * the requested range-category filter (`6` means any category).
     */
    virtual bool FindWeaponBy(std::int32_t rangeCategoryFilter, float* outMinRange, float* outMaxRange) const;

    /**
     * Address: 0x008BFD70
     * Slot: 18
     * Demangled: moho::UserUnit::GetWaterIntel
     *
     * What it does:
     * Returns active intel ranges (`omni`, `radar`, `sonar`) unless Intel
     * toggle state currently disables this block.
     *
     * Naming note:
     * Emit labels this slot as `GetWaterIntel`, but binary behavior and
     * patch-side callsites use it as a general intel-range query.
     */
    virtual bool GetIntelRanges(float* outOmniRange, float* outRadarRange, float* outSonarRange) const;

    /**
     * Address: 0x008BFE50
     * Slot: 19
     * Demangled: moho::UserUnit::GetMaxCounterIntel
     *
     * What it does:
     * Computes the largest active counter-intel radius from replicated
     * intel ranges and blueprint jam/spoof maxima.
     */
    virtual bool GetMaxCounterIntel(float* outMaxCounterIntelRange) const;

    /**
     * Address: 0x008BEFD0
     * Slot: 20
     * Demangled: moho::UserUnit::GetAutoMode
     *
     * What it does:
     * Returns UI mirror of auto-mode state.
     */
    virtual bool GetAutoMode() const;

    /**
     * Address: 0x008BEFE0
     * Slot: 21
     * Demangled: moho::UserUnit::IsAutoSurfaceMode
     *
     * What it does:
     * Returns UI mirror of auto-surface mode state.
     */
    virtual bool IsAutoSurfaceMode() const;

    /**
     * Address: 0x008BEFF0
     * Slot: 22
     * Demangled: moho::UserUnit::Func1
     *
     * What it does:
     * Returns UI mirror of repeat-queue state.
     */
    virtual bool Func1() const;

    /**
     * Address: 0x008BF000
     * Slot: 23
     * Demangled: moho::UserUnit::IsOverchargePaused
     *
     * What it does:
     * Returns whether overcharge is currently paused in UI state.
     */
    virtual bool IsOverchargePaused() const;

    /**
     * Address: 0x008BF010
     * Slot: 24
     * Demangled: moho::UserUnit::GetCustomName
     *
     * What it does:
     * Returns the in-object custom-name storage anchor at offset +0x1DC.
     */
    virtual char* GetCustomName();

    /**
     * Address: 0x008BF060
     * Slot: 25
     * Demangled: moho::UserUnit::GetFuel
     *
     * What it does:
     * Returns UI fuel ratio.
     */
    virtual float GetFuel() const;

    /**
     * Address: 0x008BF070
     * Slot: 26
     * Demangled: moho::UserUnit::GetShield
     *
     * What it does:
     * Returns UI shield ratio.
     */
    virtual float GetShield() const;

    /**
     * Address: 0x008C0D30 (FUN_008C0D30, Moho::UserUnit::CanAttackTarget)
     *
     * What it does:
     * Evaluates whether this unit can attack one optional target entity,
     * including layer/category filters and optional range checks.
     */
    [[nodiscard]] bool CanAttackTarget(const UserEntity* targetEntity, bool rangeCheck) const;

    /**
     * Address: 0x00893080 (FUN_00893080, Moho::UserUnit::AddSelectionSet)
     *
     * What it does:
     * Inserts one selection-set name into this unit's persisted selection-set
     * container.
     */
    void AddSelectionSet(const char* selectionSetName);

    /**
     * Address: 0x008BF190 (FUN_008BF190, Moho::UserUnit::RemoveSelectionSet)
     *
     * What it does:
     * Removes one selection-set name from this unit's persisted
     * selection-set container.
     */
    void RemoveSelectionSet(const char* selectionSetName);

    /**
     * Address: 0x008BF220 (FUN_008BF220, Moho::UserUnit::HasSelectionSet)
     *
     * What it does:
     * Returns whether this unit currently stores one named selection-set key.
     */
    bool HasSelectionSet(const char* selectionSetName) const;

    [[nodiscard]] bool IsRepeatQueueEnabled() const;

  public:
    // RTTI for UserUnit shows secondary subobjects:
    // +0x148: IUnit subobject (22-slot vtable), +0x150: CScriptObject-style 4-slot subobject.
    std::uint8_t mIUnitAndScriptBridge[0x190 - 0x148]{};
    bool mIsFake; // 0x0190
    std::uint8_t pad_0191_01A0[0x1A0 - 0x191]{};
    bool mAutoMode;           // 0x01A0
    bool mAutoSurfaceMode;    // 0x01A1
    bool mSelectableOverride; // 0x01A2
    std::uint8_t pad_01A3_01A4[0x1A4 - 0x1A3]{};
    float mFuelRatio;   // 0x01A4
    float mShieldRatio; // 0x01A8
    std::uint8_t pad_01AC_01B0[0x1B0 - 0x1AC]{};

    // 0x1B0
    bool mPaused;

    // 0x1B1..0x1BB - pad to float alignment
    std::uint8_t pad_01B1_01B2[0x1B2 - 0x1B1]{};
    bool mRepeatQueueEnabled; // 0x01B2
    std::uint8_t pad_01B3_01B8[0x1B8 - 0x1B3]{};
    std::int32_t mFireState; // 0x01B8

    // 0x1BC
    float mWorkProgress; // normalized work/build progress for UI

    // 0x1C0..0x1DB - unknown
    std::uint8_t pad_01C0_01DC[0x1DC - 0x1C0]{};

    // 0x1DC
    char mCustomNameStorage[0x04]; // getter returns this + 0x1DC

    // 0x1E0..0x28F - unknown
    std::uint8_t pad_01E0_0290[0x290 - 0x1E0]{};

    // 0x290
    UserUnitWeapon* mWeaponTable;    // 0x0290 (begin pointer)
    UserUnitWeapon* mWeaponTableEnd; // 0x0294 (end pointer, one-past-last)

    std::uint8_t pad_0298_03A8[0x3A8 - 0x298]{};
    std::uint8_t mIntelToggleStateMask; // 0x03A8 (INTEL/JAM/STEALTH toggle-state bits)
    std::uint8_t pad_03A9_03B9[0x3B9 - 0x3A9]{};
    bool mOverchargePaused; // 0x03B9
    std::uint8_t pad_03BA_03C8[0x3C8 - 0x3BA]{};
    UserUnitManager* mManager;        // 0x03C8
    UserUnitManager* mFactoryManager; // 0x03CC
    msvc8::set<msvc8::string> mSelectionSets; // 0x03D0
    bool mQueueEmptyCached;          // 0x03DC
    bool mIsEngineer; // 0x03DD
    bool mIsFactory;  // 0x03DE
    std::uint8_t pad_03DF_03E0[0x03E0 - 0x03DF]{};
    std::uint32_t mIntelStateFlags; // 0x03E0
    std::uint8_t pad_03E4_03E8[0x3E8 - 0x03E4]{};
  };
#if defined(MOHO_STRICT_LAYOUT_ASSERTS)
  static_assert(sizeof(UserUnit) == 0x3E8, "UserUnit size must be 0x3E8");
  static_assert(offsetof(UserUnit, mAutoMode) == 0x01A0, "UserUnit::mAutoMode offset must be 0x01A0");
  static_assert(offsetof(UserUnit, mAutoSurfaceMode) == 0x01A1, "UserUnit::mAutoSurfaceMode offset must be 0x01A1");
  static_assert(
    offsetof(UserUnit, mRepeatQueueEnabled) == 0x01B2, "UserUnit::mRepeatQueueEnabled offset must be 0x01B2"
  );
  static_assert(offsetof(UserUnit, mFireState) == 0x01B8, "UserUnit::mFireState offset must be 0x01B8");
  static_assert(offsetof(UserUnit, mCustomNameStorage) == 0x01DC, "UserUnit::mCustomNameStorage offset must be 0x01DC");
  static_assert(offsetof(UserUnit, mWeaponTable) == 0x0290, "UserUnit::mWeaponTable offset must be 0x0290");
  static_assert(offsetof(UserUnit, mWeaponTableEnd) == 0x0294, "UserUnit::mWeaponTableEnd offset must be 0x0294");
  static_assert(
    offsetof(UserUnit, mIntelToggleStateMask) == 0x03A8, "UserUnit::mIntelToggleStateMask offset must be 0x03A8"
  );
  static_assert(offsetof(UserUnit, mOverchargePaused) == 0x03B9, "UserUnit::mOverchargePaused offset must be 0x03B9");
  static_assert(
    offsetof(UserUnit, mManager) == 0x03C8, "UserUnit::mManager offset must be 0x03C8"
  );
  static_assert(
    offsetof(UserUnit, mFactoryManager) == 0x03CC,
    "UserUnit::mFactoryManager offset must be 0x03CC"
  );
  static_assert(offsetof(UserUnit, mSelectionSets) == 0x03D0, "UserUnit::mSelectionSets offset must be 0x03D0");
  static_assert(offsetof(UserUnit, mQueueEmptyCached) == 0x03DC, "UserUnit::mQueueEmptyCached offset must be 0x03DC");
  static_assert(
    offsetof(UserUnit, mIsEngineer) == 0x03DD, "UserUnit::mIsEngineer offset must be 0x03DD"
  );
  static_assert(offsetof(UserUnit, mIsFactory) == 0x03DE, "UserUnit::mIsFactory offset must be 0x03DE");
  static_assert(offsetof(UserUnit, mIntelStateFlags) == 0x03E0, "UserUnit::mIntelStateFlags offset must be 0x03E0");
#endif

  /**
   * VFTABLE: 0x00E4DA4C
   * COL:  0x00E9F3C4
   */
  using UserUnitCanAttackTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA5C
   * COL:  0x00E9F328
   */
  using UserUnitGetFootPrintSize_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA64
   * COL:  0x00E9F2D8
   */
  using UserUnitGetUnitId_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA6C
   * COL:  0x00E9F288
   */
  using UserUnitGetEntityId_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA74
   * COL:  0x00E9F238
   */
  using UserUnitGetBlueprint_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA7C
   * COL:  0x00E9F1E8
   */
  using UserUnitHasUnloadCommandQueuedUp_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA84
   * COL:  0x00E9F198
   */
  using UserUnitProcessInfo_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA8C
   * COL:  0x00E9F148
   */
  using UserUnitIsAutoMode_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA94
   * COL:  0x00E9F0F8
   */
  using UserUnitIsAutoSurfaceMode_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA9C
   * COL:  0x00E9F0A8
   */
  using UserUnitIsRepeatQueue_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAA4
   * COL:  0x00E9F058
   */
  using UserUnitIsInCategory_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAAC
   * COL:  0x00E9F008
   */
  using UserUnitGetStat_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAB4
   * COL:  0x00E9EFB8
   */
  using UserUnitIsStunned_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DABC
   * COL:  0x00E9EF68
   */
  using UserUnitSetCustomName_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAC4
   * COL:  0x00E9EF18
   */
  using UserUnitGetCustomName_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DACC
   * COL:  0x00E9EEC8
   */
  using UserUnitAddSelectionSet_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAD4
   * COL:  0x00E9EE78
   */
  using UserUnitRemoveSelectionSet_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DADC
   * COL:  0x00E9EE28
   */
  using UserUnitHasSelectionSet_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAE4
   * COL:  0x00E9EDD8
   */
  using UserUnitGetSelectionSets_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAEC
   * COL:  0x00E9ED88
   */
  using UserUnitGetHealth_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAF4
   * COL:  0x00E9ED38
   */
  using UserUnitGetMaxHealth_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAFC
   * COL:  0x00E9ECE8
   */
  using UserUnitGetBuildRate_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB04
   * COL:  0x00E9EC98
   */
  using UserUnitIsOverchargePaused_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB0C
   * COL:  0x00E9EC48
   */
  using UserUnitIsDead_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB14
   * COL:  0x00E9EBF8
   */
  using UserUnitIsIdle_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB1C
   * COL:  0x00E9EBA8
   */
  using UserUnitGetFocus_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB24
   * COL:  0x00E9EB58
   */
  using UserUnitGetGuardedEntity_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB2C
   * COL:  0x00E9EB08
   */
  using UserUnitGetCreator_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB34
   * COL:  0x00E9EAB8
   */
  using UserUnitGetPosition_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB3C
   * COL:  0x00E9EA68
   */
  using UserUnitGetArmy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB44
   * COL:  0x00E9EA18
   */
  using UserUnitGetFuelRatio_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB4C
   * COL:  0x00E9E9C8
   */
  using UserUnitGetShieldRatio_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB54
   * COL:  0x00E9E978
   */
  using UserUnitGetWorkProgress_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB5C
   * COL:  0x00E9E928
   */
  using UserUnitGetEconData_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB64
   * COL:  0x00E9E8D8
   */
  using UserUnitGetCommandQueue_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB6C
   * COL:  0x00E9E888
   */
  using UserUnitGetMissileInfo_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x008C1610 (FUN_008C1610, ?USERUNIT_WithinBuildDistance@Moho@@YA_NAAVCWldSession@1@PBVRUnitBlueprint@1@ABUSCoordsVec2@1@@Z)
   *
   * What it does:
   * Checks whether all currently selected user units are within each unit's
   * own build-distance limit from the snapped placement center for one
   * candidate blueprint footprint.
   */
  bool USERUNIT_WithinBuildDistance(
    CWldSession& session, const RUnitBlueprint* buildBlueprint, const SCoordsVec2& buildPosition
  );

  /**
   * Address: 0x008C2010 (FUN_008C2010, cfunc_UserUnitCanAttackTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitCanAttackTargetL`.
   */
  int cfunc_UserUnitCanAttackTarget(lua_State* luaContext);

  /**
   * Address: 0x008C2030 (FUN_008C2030, func_UserUnitCanAttackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:CanAttackTarget(target, rangeCheck)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitCanAttackTarget_LuaFuncDef();

  /**
   * Address: 0x008C2090 (FUN_008C2090, cfunc_UserUnitCanAttackTargetL)
   *
   * What it does:
   * Resolves one user-unit, one target-entity, and one range-check flag; then
   * pushes whether the unit can attack that target.
   */
  int cfunc_UserUnitCanAttackTargetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C21D0 (FUN_008C21D0, cfunc_UserUnitGetFootPrintSize)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetFootPrintSizeL`.
   */
  int cfunc_UserUnitGetFootPrintSize(lua_State* luaContext);

  /**
   * Address: 0x008C21F0 (FUN_008C21F0, func_UserUnitGetFootPrintSize_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetFootPrintSize()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetFootPrintSize_LuaFuncDef();

  /**
   * Address: 0x008C2250 (FUN_008C2250, cfunc_UserUnitGetFootPrintSizeL)
   *
   * What it does:
   * Returns the larger footprint axis (`max(SizeX, SizeZ)`) for one user unit.
   */
  int cfunc_UserUnitGetFootPrintSizeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2340 (FUN_008C2340, cfunc_UserUnitGetUnitId)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetUnitIdL`.
   */
  int cfunc_UserUnitGetUnitId(lua_State* luaContext);

  /**
   * Address: 0x008C2360 (FUN_008C2360, func_UserUnitGetUnitId_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetUnitId()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetUnitId_LuaFuncDef();

  /**
   * Address: 0x008C23C0 (FUN_008C23C0, cfunc_UserUnitGetUnitIdL)
   *
   * What it does:
   * Pushes one user-unit blueprint id string.
   */
  int cfunc_UserUnitGetUnitIdL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2620 (FUN_008C2620, cfunc_UserUnitGetBlueprint)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetBlueprintL`.
   */
  int cfunc_UserUnitGetBlueprint(lua_State* luaContext);

  /**
   * Address: 0x008C2640 (FUN_008C2640, func_UserUnitGetBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the `blueprint = UserUnit:GetBlueprint()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetBlueprint_LuaFuncDef();

  /**
   * Address: 0x008C26A0 (FUN_008C26A0, cfunc_UserUnitGetBlueprintL)
   *
   * What it does:
   * Resolves one user unit and pushes its Lua blueprint object.
   */
  int cfunc_UserUnitGetBlueprintL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2B60 (FUN_008C2B60, cfunc_UserUnitIsAutoMode)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsAutoModeL`.
   */
  int cfunc_UserUnitIsAutoMode(lua_State* luaContext);

  /**
   * Address: 0x008C2B80 (FUN_008C2B80, func_UserUnitIsAutoMode_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsAutoMode()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitIsAutoMode_LuaFuncDef();

  /**
   * Address: 0x008C2BE0 (FUN_008C2BE0, cfunc_UserUnitIsAutoModeL)
   *
   * What it does:
   * Pushes one user-unit auto-mode flag.
   */
  int cfunc_UserUnitIsAutoModeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2CA0 (FUN_008C2CA0, cfunc_UserUnitIsAutoSurfaceMode)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitIsAutoSurfaceModeL`.
   */
  int cfunc_UserUnitIsAutoSurfaceMode(lua_State* luaContext);

  /**
   * Address: 0x008C2CC0 (FUN_008C2CC0, func_UserUnitIsAutoSurfaceMode_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsAutoSurfaceMode()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitIsAutoSurfaceMode_LuaFuncDef();

  /**
   * Address: 0x008C2D20 (FUN_008C2D20, cfunc_UserUnitIsAutoSurfaceModeL)
   *
   * What it does:
   * Pushes one user-unit auto-surface-mode flag.
   */
  int cfunc_UserUnitIsAutoSurfaceModeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2DE0 (FUN_008C2DE0, cfunc_UserUnitIsRepeatQueue)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsRepeatQueueL`.
   */
  int cfunc_UserUnitIsRepeatQueue(lua_State* luaContext);

  /**
   * Address: 0x008C2E00 (FUN_008C2E00, func_UserUnitIsRepeatQueue_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsRepeatQueue()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitIsRepeatQueue_LuaFuncDef();

  /**
   * Address: 0x008C2E60 (FUN_008C2E60, cfunc_UserUnitIsRepeatQueueL)
   *
   * What it does:
   * Pushes one user-unit repeat-queue flag.
   */
  int cfunc_UserUnitIsRepeatQueueL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C24A0 (FUN_008C24A0, cfunc_UserUnitGetEntityId)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_UserUnitGetEntityIdL`.
   */
  int cfunc_UserUnitGetEntityId(lua_State* luaContext);

  /**
   * Address: 0x008C24C0 (FUN_008C24C0, func_UserUnitGetEntityId_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetEntityId()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetEntityId_LuaFuncDef();

  /**
   * Address: 0x008C2520 (FUN_008C2520, cfunc_UserUnitGetEntityIdL)
   *
   * What it does:
   * Validates one `UserUnit` argument and pushes its entity id as string.
   */
  int cfunc_UserUnitGetEntityIdL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2790 (FUN_008C2790, cfunc_UserUnitHasUnloadCommandQueuedUp)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitHasUnloadCommandQueuedUpL`.
   */
  int cfunc_UserUnitHasUnloadCommandQueuedUp(lua_State* luaContext);

  /**
   * Address: 0x008C27B0 (FUN_008C27B0, func_UserUnitHasUnloadCommandQueuedUp_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:HasUnloadCommandQueuedUp()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitHasUnloadCommandQueuedUp_LuaFuncDef();

  /**
   * Address: 0x008C2810 (FUN_008C2810, cfunc_UserUnitHasUnloadCommandQueuedUpL)
   *
   * What it does:
   * Returns whether the transport this unit is attached to already has an
   * unload command queued.
   */
  int cfunc_UserUnitHasUnloadCommandQueuedUpL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C29D0 (FUN_008C29D0, cfunc_UserUnitProcessInfo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitProcessInfoL`.
   */
  int cfunc_UserUnitProcessInfo(lua_State* luaContext);

  /**
   * Address: 0x008C29F0 (FUN_008C29F0, func_UserUnitProcessInfo_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:ProcessInfoPair(key, value)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitProcessInfo_LuaFuncDef();

  /**
   * Address: 0x008C2A50 (FUN_008C2A50, cfunc_UserUnitProcessInfoL)
   *
   * What it does:
   * Validates `UserUnit`, key, and value arguments, then forwards one
   * process-info pair update to the active sim driver.
   */
  int cfunc_UserUnitProcessInfoL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3580 (FUN_008C3580, cfunc_UserUnitSetCustomName)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitSetCustomNameL`.
   */
  int cfunc_UserUnitSetCustomName(lua_State* luaContext);

  /**
   * Address: 0x008C35A0 (FUN_008C35A0, func_UserUnitSetCustomName_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:SetCustomName(name)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitSetCustomName_LuaFuncDef();

  /**
   * Address: 0x008C3600 (FUN_008C3600, cfunc_UserUnitSetCustomNameL)
   *
   * What it does:
   * Validates one `UserUnit` and one custom-name string, then forwards the
   * update as a `ProcessInfoPair("CustomName", value)` command.
   */
  int cfunc_UserUnitSetCustomNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3880 (FUN_008C3880, cfunc_UserUnitAddSelectionSet)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitAddSelectionSetL`.
   */
  int cfunc_UserUnitAddSelectionSet(lua_State* luaContext);

  /**
   * Address: 0x008C38A0 (FUN_008C38A0, func_UserUnitAddSelectionSet_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:AddSelectionSet(name)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitAddSelectionSet_LuaFuncDef();

  /**
   * Address: 0x008C3900 (FUN_008C3900, cfunc_UserUnitAddSelectionSetL)
   *
   * What it does:
   * Resolves one `UserUnit` plus one selection-set name and inserts the name
   * into the unit's selection-set container.
   */
  int cfunc_UserUnitAddSelectionSetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C39E0 (FUN_008C39E0, cfunc_UserUnitRemoveSelectionSet)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitRemoveSelectionSetL`.
   */
  int cfunc_UserUnitRemoveSelectionSet(lua_State* luaContext);

  /**
   * Address: 0x008C3A00 (FUN_008C3A00, func_UserUnitRemoveSelectionSet_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:RemoveSelectionSet(name)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitRemoveSelectionSet_LuaFuncDef();

  /**
   * Address: 0x008C3A60 (FUN_008C3A60, cfunc_UserUnitRemoveSelectionSetL)
   *
   * What it does:
   * Resolves one `UserUnit` plus one selection-set name and erases that name
   * from the unit's selection-set container.
   */
  int cfunc_UserUnitRemoveSelectionSetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3CD0 (FUN_008C3CD0, cfunc_UserUnitGetSelectionSets)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetSelectionSetsL`.
   */
  int cfunc_UserUnitGetSelectionSets(lua_State* luaContext);

  /**
   * Address: 0x008C3CF0 (FUN_008C3CF0, func_UserUnitGetSelectionSets_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetSelectionSets()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetSelectionSets_LuaFuncDef();

  /**
   * Address: 0x008C3D50 (FUN_008C3D50, cfunc_UserUnitGetSelectionSetsL)
   *
   * What it does:
   * Returns a Lua array of selection-set names currently attached to one
   * `UserUnit`.
   */
  int cfunc_UserUnitGetSelectionSetsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2F20 (FUN_008C2F20, cfunc_UserUnitIsInCategory)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitIsInCategoryL`.
   */
  int cfunc_UserUnitIsInCategory(lua_State* luaContext);

  /**
   * Address: 0x008C2F40 (FUN_008C2F40, func_UserUnitIsInCategory_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsInCategory(category)` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitIsInCategory_LuaFuncDef();

  /**
   * Address: 0x008C2FA0 (FUN_008C2FA0, cfunc_UserUnitIsInCategoryL)
   *
   * What it does:
   * Returns whether one `UserUnit` matches one category string argument.
   */
  int cfunc_UserUnitIsInCategoryL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3EA0 (FUN_008C3EA0, cfunc_UserUnitGetHealth)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetHealthL`.
   */
  int cfunc_UserUnitGetHealth(lua_State* luaContext);

  /**
   * Address: 0x008C3EC0 (FUN_008C3EC0, func_UserUnitGetHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetHealth()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetHealth_LuaFuncDef();

  /**
   * Address: 0x008C3F20 (FUN_008C3F20, cfunc_UserUnitGetHealthL)
   *
   * What it does:
   * Returns current health for one user-unit as Lua number.
   */
  int cfunc_UserUnitGetHealthL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3FE0 (FUN_008C3FE0, cfunc_UserUnitGetMaxHealth)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetMaxHealthL`.
   */
  int cfunc_UserUnitGetMaxHealth(lua_State* luaContext);

  /**
   * Address: 0x008C4000 (FUN_008C4000, func_UserUnitGetMaxHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetMaxHealth()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetMaxHealth_LuaFuncDef();

  /**
   * Address: 0x008C4060 (FUN_008C4060, cfunc_UserUnitGetMaxHealthL)
   *
   * What it does:
   * Returns max health for one user-unit as Lua number.
   */
  int cfunc_UserUnitGetMaxHealthL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4120 (FUN_008C4120, cfunc_UserUnitGetBuildRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetBuildRateL`.
   */
  int cfunc_UserUnitGetBuildRate(lua_State* luaContext);

  /**
   * Address: 0x008C4140 (FUN_008C4140, func_UserUnitGetBuildRate_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetBuildRate()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetBuildRate_LuaFuncDef();

  /**
   * Address: 0x008C41A0 (FUN_008C41A0, cfunc_UserUnitGetBuildRateL)
   *
   * What it does:
   * Returns current build-rate value for one user-unit as Lua number.
   */
  int cfunc_UserUnitGetBuildRateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4270 (FUN_008C4270, cfunc_UserUnitIsOverchargePaused)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsOverchargePausedL`.
   */
  int cfunc_UserUnitIsOverchargePaused(lua_State* luaContext);

  /**
   * Address: 0x008C4290 (FUN_008C4290, func_UserUnitIsOverchargePaused_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsOverchargePaused()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitIsOverchargePaused_LuaFuncDef();

  /**
   * Address: 0x008C42F0 (FUN_008C42F0, cfunc_UserUnitIsOverchargePausedL)
   *
   * What it does:
   * Returns overcharge-paused state for one user-unit as Lua boolean.
   */
  int cfunc_UserUnitIsOverchargePausedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C43B0 (FUN_008C43B0, cfunc_UserUnitIsDead)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsDeadL`.
   */
  int cfunc_UserUnitIsDead(lua_State* luaContext);

  /**
   * Address: 0x008C43D0 (FUN_008C43D0, func_UserUnitIsDead_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsDead()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitIsDead_LuaFuncDef();

  /**
   * Address: 0x008C4430 (FUN_008C4430, cfunc_UserUnitIsDeadL)
   *
   * What it does:
   * Returns true when input user-unit is missing or reports dead.
   */
  int cfunc_UserUnitIsDeadL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4DA0 (FUN_008C4DA0, cfunc_UserUnitGetFuelRatio)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetFuelRatioL`.
   */
  int cfunc_UserUnitGetFuelRatio(lua_State* luaContext);

  /**
   * Address: 0x008C4DC0 (FUN_008C4DC0, func_UserUnitGetFuelRatio_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetFuelRatio()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetFuelRatio_LuaFuncDef();

  /**
   * Address: 0x008C4E20 (FUN_008C4E20, cfunc_UserUnitGetFuelRatioL)
   *
   * What it does:
   * Returns current fuel ratio for one user-unit as Lua number.
   */
  int cfunc_UserUnitGetFuelRatioL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4EE0 (FUN_008C4EE0, cfunc_UserUnitGetShieldRatio)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetShieldRatioL`.
   */
  int cfunc_UserUnitGetShieldRatio(lua_State* luaContext);

  /**
   * Address: 0x008C4F00 (FUN_008C4F00, func_UserUnitGetShieldRatio_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetShieldRatio()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetShieldRatio_LuaFuncDef();

  /**
   * Address: 0x008C4F60 (FUN_008C4F60, cfunc_UserUnitGetShieldRatioL)
   *
   * What it does:
   * Returns current shield ratio for one user-unit as Lua number.
   */
  int cfunc_UserUnitGetShieldRatioL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C5020 (FUN_008C5020, cfunc_UserUnitGetWorkProgress)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetWorkProgressL`.
   */
  int cfunc_UserUnitGetWorkProgress(lua_State* luaContext);

  /**
   * Address: 0x008C5040 (FUN_008C5040, func_UserUnitGetWorkProgress_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetWorkProgress()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetWorkProgress_LuaFuncDef();

  /**
   * Address: 0x008C50A0 (FUN_008C50A0, cfunc_UserUnitGetWorkProgressL)
   *
   * What it does:
   * Returns current unit work-progress ratio as Lua number.
   */
  int cfunc_UserUnitGetWorkProgressL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C30E0 (FUN_008C30E0, cfunc_UserUnitGetStat)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetStatL`.
   */
  int cfunc_UserUnitGetStat(lua_State* luaContext);

  /**
   * Address: 0x008C3100 (FUN_008C3100, func_UserUnitGetStat_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetStat(name[, defaultVal])` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetStat_LuaFuncDef();

  /**
   * Address: 0x008C3160 (FUN_008C3160, cfunc_UserUnitGetStatL)
   *
   * What it does:
   * Resolves one stat query (with optional default) and pushes one stat-table
   * result, or `nil`.
   */
  int cfunc_UserUnitGetStatL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3440 (FUN_008C3440, cfunc_UserUnitIsStunned)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitIsStunnedL`.
   */
  int cfunc_UserUnitIsStunned(lua_State* luaContext);

  /**
   * Address: 0x008C3460 (FUN_008C3460, func_UserUnitIsStunned_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsStunned()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitIsStunned_LuaFuncDef();

  /**
   * Address: 0x008C34C0 (FUN_008C34C0, cfunc_UserUnitIsStunnedL)
   *
   * What it does:
   * Pushes one stunned-state boolean from replicated user-unit runtime state.
   */
  int cfunc_UserUnitIsStunnedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3700 (FUN_008C3700, cfunc_UserUnitGetCustomName)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetCustomNameL`.
   */
  int cfunc_UserUnitGetCustomName(lua_State* luaContext);

  /**
   * Address: 0x008C3720 (FUN_008C3720, func_UserUnitGetCustomName_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetCustomName()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetCustomName_LuaFuncDef();

  /**
   * Address: 0x008C3780 (FUN_008C3780, cfunc_UserUnitGetCustomNameL)
   *
   * What it does:
   * Pushes one custom-name string (or `nil` when empty).
   */
  int cfunc_UserUnitGetCustomNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3B40 (FUN_008C3B40, cfunc_UserUnitHasSelectionSet)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitHasSelectionSetL`.
   */
  int cfunc_UserUnitHasSelectionSet(lua_State* luaContext);

  /**
   * Address: 0x008C3B60 (FUN_008C3B60, func_UserUnitHasSelectionSet_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:HasSelectionSet(name)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitHasSelectionSet_LuaFuncDef();

  /**
   * Address: 0x008C3BC0 (FUN_008C3BC0, cfunc_UserUnitHasSelectionSetL)
   *
   * What it does:
   * Pushes one boolean membership result for the provided selection-set name.
   */
  int cfunc_UserUnitHasSelectionSetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4500 (FUN_008C4500, cfunc_UserUnitIsIdle)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsIdleL`.
   */
  int cfunc_UserUnitIsIdle(lua_State* luaContext);

  /**
   * Address: 0x008C4520 (FUN_008C4520, func_UserUnitIsIdle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsIdle()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitIsIdle_LuaFuncDef();

  /**
   * Address: 0x008C4580 (FUN_008C4580, cfunc_UserUnitIsIdleL)
   *
   * What it does:
   * Pushes one idle-state boolean derived from busy + queue-empty state.
   */
  int cfunc_UserUnitIsIdleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4660 (FUN_008C4660, cfunc_UserUnitGetFocus)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetFocusL`.
   */
  int cfunc_UserUnitGetFocus(lua_State* luaContext);

  /**
   * Address: 0x008C4680 (FUN_008C4680, func_UserUnitGetFocus_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetFocus()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetFocus_LuaFuncDef();

  /**
   * Address: 0x008C46E0 (FUN_008C46E0, cfunc_UserUnitGetFocusL)
   *
   * What it does:
   * Pushes focused target user-unit Lua object, or `nil` when unresolved.
   */
  int cfunc_UserUnitGetFocusL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C47F0 (FUN_008C47F0, cfunc_UserUnitGetGuardedEntity)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetGuardedEntityL`.
   */
  int cfunc_UserUnitGetGuardedEntity(lua_State* luaContext);

  /**
   * Address: 0x008C4810 (FUN_008C4810, func_UserUnitGetGuardedEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetGuardedEntity()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetGuardedEntity_LuaFuncDef();

  /**
   * Address: 0x008C4870 (FUN_008C4870, cfunc_UserUnitGetGuardedEntityL)
   *
   * What it does:
   * Pushes guarded-target user-unit Lua object, or `nil` when unresolved.
   */
  int cfunc_UserUnitGetGuardedEntityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4980 (FUN_008C4980, cfunc_UserUnitGetCreator)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetCreatorL`.
   */
  int cfunc_UserUnitGetCreator(lua_State* luaContext);

  /**
   * Address: 0x008C49A0 (FUN_008C49A0, func_UserUnitGetCreator_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetCreator()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetCreator_LuaFuncDef();

  /**
   * Address: 0x008C4A00 (FUN_008C4A00, cfunc_UserUnitGetCreatorL)
   *
   * What it does:
   * Pushes creator user-unit Lua object, or `nil` when unavailable.
   */
  int cfunc_UserUnitGetCreatorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4AF0 (FUN_008C4AF0, cfunc_UserUnitGetPosition)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetPositionL`.
   */
  int cfunc_UserUnitGetPosition(lua_State* luaContext);

  /**
   * Address: 0x008C4B10 (FUN_008C4B10, func_UserUnitGetPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetPosition()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetPosition_LuaFuncDef();

  /**
   * Address: 0x008C4B70 (FUN_008C4B70, cfunc_UserUnitGetPositionL)
   *
   * What it does:
   * Pushes world position as one Lua VECTOR3 object.
   */
  int cfunc_UserUnitGetPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4C50 (FUN_008C4C50, cfunc_UserUnitGetArmy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetArmyL`.
   */
  int cfunc_UserUnitGetArmy(lua_State* luaContext);

  /**
   * Address: 0x008C4C70 (FUN_008C4C70, func_UserUnitGetArmy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetArmy()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetArmy_LuaFuncDef();

  /**
   * Address: 0x008C4CD0 (FUN_008C4CD0, cfunc_UserUnitGetArmyL)
   *
   * What it does:
   * Pushes one-based army index for the unit owner, preserving `-1` sentinel.
   */
  int cfunc_UserUnitGetArmyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C5160 (FUN_008C5160, cfunc_UserUnitGetEconData)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetEconDataL`.
   */
  int cfunc_UserUnitGetEconData(lua_State* luaContext);

  /**
   * Address: 0x008C5180 (FUN_008C5180, func_UserUnitGetEconData_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetEconData()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetEconData_LuaFuncDef();

  /**
   * Address: 0x008C51E0 (FUN_008C51E0, cfunc_UserUnitGetEconDataL)
   *
   * What it does:
   * Pushes one Lua table with per-second economy lanes for this user unit.
   */
  int cfunc_UserUnitGetEconDataL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C5400 (FUN_008C5400, cfunc_UserUnitGetCommandQueue)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetCommandQueueL`.
   */
  int cfunc_UserUnitGetCommandQueue(lua_State* luaContext);

  /**
   * Address: 0x008C5420 (FUN_008C5420, func_UserUnitGetCommandQueue_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetCommandQueue()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetCommandQueue_LuaFuncDef();

  /**
   * Address: 0x008C5480 (FUN_008C5480, cfunc_UserUnitGetCommandQueueL)
   *
   * What it does:
   * Pushes one Lua array of queued command descriptors (`ID`, `type`,
   * `position`) for this user unit.
   */
  int cfunc_UserUnitGetCommandQueueL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C5750 (FUN_008C5750, cfunc_UserUnitGetMissileInfo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetMissileInfoL`.
   */
  int cfunc_UserUnitGetMissileInfo(lua_State* luaContext);

  /**
   * Address: 0x008C5770 (FUN_008C5770, func_UserUnitGetMissileInfo_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetMissileInfo()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetMissileInfo_LuaFuncDef();

  /**
   * Address: 0x008C57D0 (FUN_008C57D0, cfunc_UserUnitGetMissileInfoL)
   *
   * What it does:
   * Pushes one Lua table with tactical/nuke silo build and storage counters.
   */
  int cfunc_UserUnitGetMissileInfoL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00836360 (FUN_00836360, cfunc_SetCurrentFactoryForQueueDisplay)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_SetCurrentFactoryForQueueDisplayL`.
   */
  int cfunc_SetCurrentFactoryForQueueDisplay(lua_State* luaContext);

  /**
   * Address: 0x00836380 (FUN_00836380, func_SetCurrentFactoryForQueueDisplay_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `SetCurrentFactoryForQueueDisplay(unit)` Lua binder.
   */
  CScrLuaInitForm* func_SetCurrentFactoryForQueueDisplay_LuaFuncDef();

  /**
   * Address: 0x008363E0 (FUN_008363E0, cfunc_SetCurrentFactoryForQueueDisplayL)
   *
   * What it does:
   * Rebuilds current UI factory queue view from one optional user-unit object
   * and pushes the resulting queue table (or nil).
   */
  int cfunc_SetCurrentFactoryForQueueDisplayL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C5930 (FUN_008C5930, cfunc_GetBlueprintUser)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetBlueprintUserL`.
   */
  int cfunc_GetBlueprintUser(lua_State* luaContext);

  /**
   * Address: 0x008C5950 (FUN_008C5950, func_GetBlueprintUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the global user-Lua `GetBlueprint` binder.
   */
  CScrLuaInitForm* func_GetBlueprintUser_LuaFuncDef();

  /**
   * Address: 0x008C59B0 (FUN_008C59B0, cfunc_GetBlueprintUserL)
   *
   * What it does:
   * Resolves one `UserUnit` Lua object argument and pushes its unit blueprint
   * Lua object result.
   */
  int cfunc_GetBlueprintUserL(LuaPlus::LuaState* state);

} // namespace moho
