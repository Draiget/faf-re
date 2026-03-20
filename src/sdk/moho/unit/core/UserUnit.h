// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "moho/lua/CScrLuaBinderFwd.h"

#include <cstddef>
#include <cstdint>

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class SSTIEntityVariableData;
  class UserUnitWeapon;
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
     * Demangled: sub_8BF990
     */
    virtual void sub_8BF990() = 0;

    /**
     * Address: 0x008C0A30
     * Slot: 1
     * Demangled: moho::UserUnit::Tick
     *
     * What it does:
     * Per-beat update hook for UI unit state.
     */
    virtual void Tick(std::int32_t seqNo) = 0;

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
    virtual void UpdateEntityData(moho::SSTIEntityVariableData const&) = 0;

    /**
     * Address: 0x008C09B0
     * Slot: 10
     * Demangled: moho::UserUnit::UpdateVisibility
     */
    virtual void UpdateVisibility() = 0;

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
     */
    virtual void Select() = 0;

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
     */
    virtual void NotifyFocusArmyUnitDamaged() = 0;

    /**
     * Address: 0x008C00E0
     * Slot: 15
     * Demangled: moho::UserUnit::CreateMeshInstance
     */
    virtual void CreateMeshInstance() = 0;

    /**
     * Address: 0x008C04D0
     * Slot: 16
     * Demangled: protected: virtual void __thiscall moho::UserEntity::DestroyMeshInstance(void)
     */
    virtual void DestroyMeshInstance() = 0;

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

    [[nodiscard]] bool IsRepeatQueueEnabled() const;

  public:
    // RTTI for UserUnit shows secondary subobjects:
    // +0x148: IUnit subobject (22-slot vtable), +0x150: CScriptObject-style 4-slot subobject.
    std::uint8_t mIUnitAndScriptBridge[0x190 - 0x148]{};
    bool mSelectionMarkerLocked; // 0x0190
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
    std::uint8_t pad_01B3_01BC[0x1BC - 0x1B3]{};

    // 0x1BC
    float mWorkProgress; // normalized work/build progress for UI

    // 0x1C0..0x1DB - unknown
    std::uint8_t pad_01C0_01DC[0x1DC - 0x1C0]{};

    // 0x1DC
    char mCustomNameStorage[0x04]; // getter returns this + 0x1DC

    // 0x1E0..0x28F - unknown
    std::uint8_t pad_01E0_0290[0x290 - 0x1E0]{};

    // 0x290
    UserUnitWeapon* mWeaponTable; // weapon table for GUI/range queries

    std::uint8_t pad_0294_03A8[0x3A8 - 0x294]{};
    std::uint8_t mIntelToggleStateMask; // 0x03A8 (INTEL/JAM/STEALTH toggle-state bits)
    std::uint8_t pad_03A9_03B9[0x3B9 - 0x3A9]{};
    bool mOverchargePaused; // 0x03B9
    std::uint8_t pad_03BA_03C8[0x3C8 - 0x3BA]{};
    std::int32_t mCommandQueueHandle;        // 0x03C8
    std::int32_t mFactoryCommandQueueHandle; // 0x03CC
    std::uint8_t pad_03D0_03DC[0x03DC - 0x03D0]{};
    bool mQueueEmptyCached;          // 0x03DC
    bool mQueueAssistOverlayEnabled; // 0x03DD
    bool mQueueGuardOverlayEnabled;  // 0x03DE
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
  static_assert(offsetof(UserUnit, mCustomNameStorage) == 0x01DC, "UserUnit::mCustomNameStorage offset must be 0x01DC");
  static_assert(offsetof(UserUnit, mWeaponTable) == 0x0290, "UserUnit::mWeaponTable offset must be 0x0290");
  static_assert(
    offsetof(UserUnit, mIntelToggleStateMask) == 0x03A8, "UserUnit::mIntelToggleStateMask offset must be 0x03A8"
  );
  static_assert(offsetof(UserUnit, mOverchargePaused) == 0x03B9, "UserUnit::mOverchargePaused offset must be 0x03B9");
  static_assert(
    offsetof(UserUnit, mCommandQueueHandle) == 0x03C8, "UserUnit::mCommandQueueHandle offset must be 0x03C8"
  );
  static_assert(
    offsetof(UserUnit, mFactoryCommandQueueHandle) == 0x03CC,
    "UserUnit::mFactoryCommandQueueHandle offset must be 0x03CC"
  );
  static_assert(offsetof(UserUnit, mQueueEmptyCached) == 0x03DC, "UserUnit::mQueueEmptyCached offset must be 0x03DC");
  static_assert(
    offsetof(UserUnit, mQueueAssistOverlayEnabled) == 0x03DD,
    "UserUnit::mQueueAssistOverlayEnabled offset must be 0x03DD"
  );
  static_assert(
    offsetof(UserUnit, mQueueGuardOverlayEnabled) == 0x03DE, "UserUnit::mQueueGuardOverlayEnabled offset must be 0x03DE"
  );
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

} // namespace moho
