#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptObject.h"

#include "legacy/containers/String.h"

struct lua_State;

namespace moho
{
  class Sim;

  struct SAiPersonalityRange
  {
    float mMinValue; // +0x00
    float mMaxValue; // +0x04
  };
  static_assert(sizeof(SAiPersonalityRange) == 0x08, "SAiPersonalityRange size must be 0x08");

  /**
   * VFTABLE: 0x00E1CA14
   * COL:  0x00E72C7C
   */
  class CAiPersonality : public CScriptObject
  {
  public:
    /**
     * Address: 0x005B6DC0 (FUN_005B6DC0, ctor body)
     *
     * What it does:
     * Initializes scripting/metatable state and personality defaults.
     */
    explicit CAiPersonality(Sim* sim = nullptr);

    /**
     * Address: 0x005B6DA0 (FUN_005B6DA0, scalar deleting thunk)
     * Address: 0x005B7120 (FUN_005B7120, core dtor)
     *
     * VFTable SLOT: 2
     */
    ~CAiPersonality() override;

    /**
     * Address: 0x005B65A0 (FUN_005B65A0, ?GetClass@CAiPersonality@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 0
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x005B65C0 (FUN_005B65C0, ?GetDerivedObjectRef@CAiPersonality@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 1
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x005B7340 (FUN_005B7340, Moho::CAiPersonality::ReadData)
     *
     * What it does:
     * Loads `/lua/aipersonality.lua`, finds `AIPersonalityTemplate["AverageJoe"]`,
     * and fills all profile ranges/string lists.
     */
    void ReadData();

    /**
     * Address: 0x005B96A0 (FUN_005B96A0, Moho::CAiPersonality::MemberDeserialize)
     *
     * What it does:
     * Loads reflected CAiPersonality state fields from one read archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005B9DD0 (FUN_005B9DD0, Moho::CAiPersonality::MemberSerialize)
     *
     * What it does:
     * Saves reflected CAiPersonality state fields into one write archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    static gpg::RType* sType;

    Sim* mSim;                                // +0x34
    msvc8::string mPersonalityName;           // +0x38
    msvc8::string mChatPersonality;           // +0x54
    SAiPersonalityRange mArmySize;            // +0x70
    SAiPersonalityRange mPlatoonSize;         // +0x78
    SAiPersonalityRange mAttackFrequency;     // +0x80
    SAiPersonalityRange mRepeatAttackFrequency; // +0x88
    SAiPersonalityRange mCounterForces;       // +0x90
    SAiPersonalityRange mIntelGathering;      // +0x98
    SAiPersonalityRange mCoordinatedAttacks;  // +0xA0
    SAiPersonalityRange mExpansionDriven;     // +0xA8
    SAiPersonalityRange mTechAdvancement;     // +0xB0
    SAiPersonalityRange mUpgradesDriven;      // +0xB8
    SAiPersonalityRange mDefenseDriven;       // +0xC0
    SAiPersonalityRange mEconomyDriven;       // +0xC8
    SAiPersonalityRange mFactoryTycoon;       // +0xD0
    SAiPersonalityRange mIntelBuildingTycoon; // +0xD8
    SAiPersonalityRange mSuperWeaponTendency; // +0xE0
    msvc8::vector<msvc8::string> mFavouriteStructures; // +0xE8
    SAiPersonalityRange mAirUnitsEmphasis;            // +0xF8
    SAiPersonalityRange mTankUnitsEmphasis;           // +0x100
    SAiPersonalityRange mBotUnitsEmphasis;            // +0x108
    SAiPersonalityRange mSeaUnitsEmphasis;            // +0x110
    SAiPersonalityRange mSpecialtyForcesEmphasis;     // +0x118
    SAiPersonalityRange mSupportUnitsEmphasis;        // +0x120
    SAiPersonalityRange mDirectDamageEmphasis;        // +0x128
    SAiPersonalityRange mIndirectDamageEmphasis;      // +0x130
    msvc8::vector<msvc8::string> mFavouriteUnits;     // +0x138
    SAiPersonalityRange mSurvivalEmphasis;            // +0x148
    SAiPersonalityRange mTeamSupport;                 // +0x150
    SAiPersonalityRange mFormationUse;                // +0x158
    SAiPersonalityRange mTargetSpread;                // +0x160
    SAiPersonalityRange mQuittingTendency;            // +0x168
    SAiPersonalityRange mChatFrequency;               // +0x170
    float mDifficulty;                                // +0x178
  };

  static_assert(sizeof(CAiPersonality) == 0x17C, "CAiPersonality size must be 0x17C");
  static_assert(offsetof(CAiPersonality, mSim) == 0x34, "CAiPersonality::mSim offset must be 0x34");
  static_assert(offsetof(CAiPersonality, mPersonalityName) == 0x38, "CAiPersonality::mPersonalityName offset must be 0x38");
  static_assert(offsetof(CAiPersonality, mChatPersonality) == 0x54, "CAiPersonality::mChatPersonality offset must be 0x54");
  static_assert(offsetof(CAiPersonality, mArmySize) == 0x70, "CAiPersonality::mArmySize offset must be 0x70");
  static_assert(
    offsetof(CAiPersonality, mSuperWeaponTendency) == 0xE0,
    "CAiPersonality::mSuperWeaponTendency offset must be 0xE0"
  );
  static_assert(
    offsetof(CAiPersonality, mFavouriteStructures) == 0xE8,
    "CAiPersonality::mFavouriteStructures offset must be 0xE8"
  );
  static_assert(
    offsetof(CAiPersonality, mAirUnitsEmphasis) == 0xF8, "CAiPersonality::mAirUnitsEmphasis offset must be 0xF8"
  );
  static_assert(
    offsetof(CAiPersonality, mIndirectDamageEmphasis) == 0x130,
    "CAiPersonality::mIndirectDamageEmphasis offset must be 0x130"
  );
  static_assert(
    offsetof(CAiPersonality, mFavouriteUnits) == 0x138, "CAiPersonality::mFavouriteUnits offset must be 0x138"
  );
  static_assert(
    offsetof(CAiPersonality, mSurvivalEmphasis) == 0x148, "CAiPersonality::mSurvivalEmphasis offset must be 0x148"
  );
  static_assert(
    offsetof(CAiPersonality, mChatFrequency) == 0x170, "CAiPersonality::mChatFrequency offset must be 0x170"
  );
  static_assert(offsetof(CAiPersonality, mDifficulty) == 0x178, "CAiPersonality::mDifficulty offset must be 0x178");

  /**
   * VFTABLE: 0x00E1CAB8
   * COL:  0x00E7298C
   */
  template <>
  class CScrLuaMetatableFactory<CAiPersonality> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x005B9620 (FUN_005B9620, ?Create@?$CScrLuaMetatableFactory@VCAiPersonality@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CAiPersonality>) == 0x08,
    "CScrLuaMetatableFactory<CAiPersonality> size must be 0x08"
  );

  /**
   * Address: 0x00BCD6A0 (FUN_00BCD6A0)
   *
   * What it does:
   * Allocates and stores the startup Lua metatable-factory index for
   * `CAiPersonality`.
   */
  int register_CScrLuaMetatableFactory_CAiPersonality_Index();

  /**
   * Address: 0x00BCD6C0 (FUN_00BCD6C0)
   *
   * What it does:
   * Installs process-exit cleanup for one startup-owned AI reflection slot.
   */
  int register_CAiPersonalityStartupCleanup();

  /**
   * VFTABLE: 0x00E1D2D0
   * COL:  0x00E737CC
   */
  using CAiPersonalityGetPersonalityName_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D2D8
   * COL:  0x00E7377C
   */
  using CAiPersonalityGetChatPersonality_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D2E0
   * COL:  0x00E7372C
   */
  using CAiPersonalityGetDifficulty_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D2E8
   * COL:  0x00E736DC
   */
  using CAiPersonalityAdjustDelay_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x005BA970 (FUN_005BA970, cfunc_CAiPersonalityAdjustDelay)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAiPersonalityAdjustDelayL`.
   */
  int cfunc_CAiPersonalityAdjustDelay(lua_State* luaContext);

  /**
   * Address: 0x005BA990 (FUN_005BA990, func_CAiPersonalityAdjustDelay_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiPersonality:AdjustDelay()` Lua binder definition.
   */
  CScrLuaInitForm* func_CAiPersonalityAdjustDelay_LuaFuncDef();

  /**
   * Address: 0x005BA9F0 (FUN_005BA9F0, cfunc_CAiPersonalityAdjustDelayL)
   *
   * What it does:
   * Applies one difficulty-scaled delay adjustment and returns the final
   * integer delay value.
   */
  int cfunc_CAiPersonalityAdjustDelayL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005BBE00 (FUN_005BBE00, cfunc_CAiPersonalityGetFavouriteStructures)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAiPersonalityGetFavouriteStructuresL`.
   */
  int cfunc_CAiPersonalityGetFavouriteStructures(lua_State* luaContext);

  /**
   * Address: 0x005BBE80 (FUN_005BBE80, cfunc_CAiPersonalityGetFavouriteStructuresL)
   *
   * What it does:
   * Pushes `mFavouriteStructures` as one Lua array-table of strings.
   */
  int cfunc_CAiPersonalityGetFavouriteStructuresL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005BC9D0 (FUN_005BC9D0, cfunc_CAiPersonalityGetFavouriteUnits)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAiPersonalityGetFavouriteUnitsL`.
   */
  int cfunc_CAiPersonalityGetFavouriteUnits(lua_State* luaContext);

  /**
   * Address: 0x005BCA50 (FUN_005BCA50, cfunc_CAiPersonalityGetFavouriteUnitsL)
   *
   * What it does:
   * Pushes `mFavouriteUnits` as one Lua array-table of strings.
   */
  int cfunc_CAiPersonalityGetFavouriteUnitsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005BCF60 (FUN_005BCF60, cfunc_CAiPersonalityGetTargetSpread)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAiPersonalityGetTargetSpreadL`.
   */
  int cfunc_CAiPersonalityGetTargetSpread(lua_State* luaContext);

  /**
   * Address: 0x005BCF80 (FUN_005BCF80, func_CAiPersonalityGetTargetSpread_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiPersonality:GetTargetSpread()` Lua binder definition.
   */
  CScrLuaInitForm* func_CAiPersonalityGetTargetSpread_LuaFuncDef();

  /**
   * Address: 0x005BCFE0 (FUN_005BCFE0, cfunc_CAiPersonalityGetTargetSpreadL)
   *
   * What it does:
   * Returns one difficulty-weighted target-spread value.
   */
  int cfunc_CAiPersonalityGetTargetSpreadL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005BD0A0 (FUN_005BD0A0, cfunc_CAiPersonalityGetQuittingTendency)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAiPersonalityGetQuittingTendencyL`.
   */
  int cfunc_CAiPersonalityGetQuittingTendency(lua_State* luaContext);

  /**
   * Address: 0x005BD0C0 (FUN_005BD0C0, func_CAiPersonalityGetQuittingTendency_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiPersonality:GetQuittingTendency()` Lua binder definition.
   */
  CScrLuaInitForm* func_CAiPersonalityGetQuittingTendency_LuaFuncDef();

  /**
   * Address: 0x005BD120 (FUN_005BD120, cfunc_CAiPersonalityGetQuittingTendencyL)
   *
   * What it does:
   * Returns one difficulty-weighted quitting-tendency value.
   */
  int cfunc_CAiPersonalityGetQuittingTendencyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005BD1E0 (FUN_005BD1E0, cfunc_CAiPersonalityGetChatFrequency)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAiPersonalityGetChatFrequencyL`.
   */
  int cfunc_CAiPersonalityGetChatFrequency(lua_State* luaContext);

  /**
   * Address: 0x005BD200 (FUN_005BD200, func_CAiPersonalityGetChatFrequency_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiPersonality:GetChatFrequency()` Lua binder definition.
   */
  CScrLuaInitForm* func_CAiPersonalityGetChatFrequency_LuaFuncDef();

  /**
   * Address: 0x005BD260 (FUN_005BD260, cfunc_CAiPersonalityGetChatFrequencyL)
   *
   * What it does:
   * Returns one difficulty-weighted chat-frequency value.
   */
  int cfunc_CAiPersonalityGetChatFrequencyL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E1D2F0
   * COL:  0x00E7368C
   */
  using CAiPersonalityGetArmySize_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D2F8
   * COL:  0x00E7363C
   */
  using CAiPersonalityGetPlatoonSize_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D300
   * COL:  0x00E735EC
   */
  using CAiPersonalityGetAttackFrequency_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D308
   * COL:  0x00E7359C
   */
  using CAiPersonalityGetRepeatAttackFrequency_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D310
   * COL:  0x00E7354C
   */
  using CAiPersonalityGetCounterForces_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D318
   * COL:  0x00E734FC
   */
  using CAiPersonalityGetIntelGathering_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D320
   * COL:  0x00E734AC
   */
  using CAiPersonalityGetCoordinatedAttacks_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D328
   * COL:  0x00E7345C
   */
  using CAiPersonalityGetExpansionDriven_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D330
   * COL:  0x00E7340C
   */
  using CAiPersonalityGetTechAdvancement_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D338
   * COL:  0x00E733BC
   */
  using CAiPersonalityGetUpgradesDriven_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D340
   * COL:  0x00E7336C
   */
  using CAiPersonalityGetDefenseDriven_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D348
   * COL:  0x00E7331C
   */
  using CAiPersonalityGetEconomyDriven_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D350
   * COL:  0x00E732CC
   */
  using CAiPersonalityGetFactoryTycoon_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D358
   * COL:  0x00E7327C
   */
  using CAiPersonalityGetIntelBuildingTycoon_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D360
   * COL:  0x00E7322C
   */
  using CAiPersonalityGetSuperWeaponTendency_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D368
   * COL:  0x00E731DC
   */
  using CAiPersonalityGetFavouriteStructures_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D370
   * COL:  0x00E7318C
   */
  using CAiPersonalityGetAirUnitsEmphasis_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D378
   * COL:  0x00E7313C
   */
  using CAiPersonalityGetTankUnitsEmphasis_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D380
   * COL:  0x00E730EC
   */
  using CAiPersonalityGetBotUnitsEmphasis_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D388
   * COL:  0x00E7309C
   */
  using CAiPersonalityGetSeaUnitsEmphasis_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D390
   * COL:  0x00E7304C
   */
  using CAiPersonalityGetSpecialtyForcesEmphasis_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D398
   * COL:  0x00E72FFC
   */
  using CAiPersonalityGetSupportUnitsEmphasis_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D3A0
   * COL:  0x00E72FAC
   */
  using CAiPersonalityGetDirectDamageEmphasis_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D3A8
   * COL:  0x00E72F5C
   */
  using CAiPersonalityGetInDirectDamageEmphasis_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D3B0
   * COL:  0x00E72F0C
   */
  using CAiPersonalityGetFavouriteUnits_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D3B8
   * COL:  0x00E72EBC
   */
  using CAiPersonalityGetSurvivalEmphasis_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D3C0
   * COL:  0x00E72E6C
   */
  using CAiPersonalityGetTeamSupport_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D3C8
   * COL:  0x00E72E1C
   */
  using CAiPersonalityGetFormationUse_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D3D0
   * COL:  0x00E72DCC
   */
  using CAiPersonalityGetTargetSpread_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D3D8
   * COL:  0x00E72D7C
   */
  using CAiPersonalityGetQuittingTendency_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1D3E0
   * COL:  0x00E72D2C
   */
  using CAiPersonalityGetChatFrequency_LuaFuncDef = ::moho::CScrLuaBinder;

} // namespace moho
