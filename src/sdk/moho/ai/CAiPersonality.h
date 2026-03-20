// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "moho/lua/CScrLuaBinderFwd.h"

#include "legacy/containers/String.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  /**
   * VFTABLE: 0x00E1CA14
   * COL:  0x00E72C7C
   */
  class CAiPersonality
  {
  public:
    /**
     * Address: 0x005B65A0
     * Slot: 0
     * Demangled: Moho::CAiPersonality::GetClass
     */
    virtual void GetClass() = 0;

    /**
     * Address: 0x005B65C0
     * Slot: 1
     * Demangled: GetDerivedObjectRef
     */
    virtual void GetDerivedObjectRef() = 0;

    /**
     * Address: 0x005B6DA0
     * Slot: 2
     * Demangled: (likely scalar deleting destructor thunk)
     */
    virtual ~CAiPersonality() = default;

    /**
     * Address: 0x004C70A0
     * Slot: 3
     * Demangled: public: virtual class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>>
     * __thiscall Moho::CScriptObject::GetErrorDescription(void)const
     */
    virtual msvc8::string GetErrorDescription() const = 0;
  };

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
