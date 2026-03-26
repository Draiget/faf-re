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
    float mAdjustDelay;                               // +0x178
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
  static_assert(offsetof(CAiPersonality, mAdjustDelay) == 0x178, "CAiPersonality::mAdjustDelay offset must be 0x178");

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
