// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "legacy/containers/String.h"

namespace LuaPlus { class LuaObject; class LuaState; } // forward decl

namespace moho {
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
     * Demangled: sub_5B65A0
     */
    virtual void sub_5B65A0() = 0;

    /**
     * Address: 0x005B65C0
     * Slot: 1
     * Demangled: sub_5B65C0
     */
    virtual void sub_5B65C0() = 0;

    /**
     * Address: 0x005B6DA0
     * Slot: 2
     * Demangled: sub_5B6DA0
     */
    virtual void sub_5B6DA0() = 0;

    /**
     * Address: 0x004C70A0
     * Slot: 3
     * Demangled: public: virtual class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>> __thiscall Moho::CScriptObject::GetErrorDescription(void)const
     */
    virtual msvc8::string GetErrorDescription() const = 0;
  };

/**
 * VFTABLE: 0x00E1D2D0
 * COL:  0x00E737CC
 */
class CAiPersonalityGetPersonalityName_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D2D8
 * COL:  0x00E7377C
 */
class CAiPersonalityGetChatPersonality_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D2E0
 * COL:  0x00E7372C
 */
class CAiPersonalityGetDifficulty_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D2E8
 * COL:  0x00E736DC
 */
class CAiPersonalityAdjustDelay_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D2F0
 * COL:  0x00E7368C
 */
class CAiPersonalityGetArmySize_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D2F8
 * COL:  0x00E7363C
 */
class CAiPersonalityGetPlatoonSize_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D300
 * COL:  0x00E735EC
 */
class CAiPersonalityGetAttackFrequency_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D308
 * COL:  0x00E7359C
 */
class CAiPersonalityGetRepeatAttackFrequency_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D310
 * COL:  0x00E7354C
 */
class CAiPersonalityGetCounterForces_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D318
 * COL:  0x00E734FC
 */
class CAiPersonalityGetIntelGathering_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D320
 * COL:  0x00E734AC
 */
class CAiPersonalityGetCoordinatedAttacks_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D328
 * COL:  0x00E7345C
 */
class CAiPersonalityGetExpansionDriven_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D330
 * COL:  0x00E7340C
 */
class CAiPersonalityGetTechAdvancement_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D338
 * COL:  0x00E733BC
 */
class CAiPersonalityGetUpgradesDriven_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D340
 * COL:  0x00E7336C
 */
class CAiPersonalityGetDefenseDriven_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D348
 * COL:  0x00E7331C
 */
class CAiPersonalityGetEconomyDriven_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D350
 * COL:  0x00E732CC
 */
class CAiPersonalityGetFactoryTycoon_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D358
 * COL:  0x00E7327C
 */
class CAiPersonalityGetIntelBuildingTycoon_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D360
 * COL:  0x00E7322C
 */
class CAiPersonalityGetSuperWeaponTendency_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D368
 * COL:  0x00E731DC
 */
class CAiPersonalityGetFavouriteStructures_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D370
 * COL:  0x00E7318C
 */
class CAiPersonalityGetAirUnitsEmphasis_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D378
 * COL:  0x00E7313C
 */
class CAiPersonalityGetTankUnitsEmphasis_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D380
 * COL:  0x00E730EC
 */
class CAiPersonalityGetBotUnitsEmphasis_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D388
 * COL:  0x00E7309C
 */
class CAiPersonalityGetSeaUnitsEmphasis_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D390
 * COL:  0x00E7304C
 */
class CAiPersonalityGetSpecialtyForcesEmphasis_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D398
 * COL:  0x00E72FFC
 */
class CAiPersonalityGetSupportUnitsEmphasis_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D3A0
 * COL:  0x00E72FAC
 */
class CAiPersonalityGetDirectDamageEmphasis_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D3A8
 * COL:  0x00E72F5C
 */
class CAiPersonalityGetInDirectDamageEmphasis_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D3B0
 * COL:  0x00E72F0C
 */
class CAiPersonalityGetFavouriteUnits_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D3B8
 * COL:  0x00E72EBC
 */
class CAiPersonalityGetSurvivalEmphasis_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D3C0
 * COL:  0x00E72E6C
 */
class CAiPersonalityGetTeamSupport_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D3C8
 * COL:  0x00E72E1C
 */
class CAiPersonalityGetFormationUse_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D3D0
 * COL:  0x00E72DCC
 */
class CAiPersonalityGetTargetSpread_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D3D8
 * COL:  0x00E72D7C
 */
class CAiPersonalityGetQuittingTendency_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E1D3E0
 * COL:  0x00E72D2C
 */
class CAiPersonalityGetChatFrequency_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

} // namespace moho
