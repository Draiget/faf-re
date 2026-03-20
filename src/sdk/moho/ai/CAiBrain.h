// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "moho/lua/CScrLuaBinderFwd.h"

#include "legacy/containers/String.h"

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E19900
   * COL:  0x00E6EA10
   */
  class CAiBrain
  {
  public:
    /**
     * Address: 0x00579590
     * Slot: 0
     * Demangled: Moho::CAiBrain::GetClass
     */
    virtual void GetClass() = 0;
    /**
     * Address: 0x005795B0
     * Slot: 1
     * Demangled: Moho::CAiBrain::GetDerivedObjectRef
     */
    virtual void GetDerivedObjectRef() = 0;
    /**
     * Address: 0x00579F30
     * Slot: 2
     * Demangled: (likely scalar deleting destructor thunk)
     */
    virtual ~CAiBrain() = default;
    /**
     * Address: 0x004C70A0
     * Slot: 3
     * Demangled: public: virtual class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>>
     * __thiscall Moho::CScriptObject::GetErrorDescription(void)const
     */
    virtual msvc8::string GetErrorDescription() const = 0;
  };
} // namespace moho

/**
 * VFTABLE: 0x00E1AF5C
 * COL:  0x00E6FFD8
 */
using CAiBrainIsOpponentAIRunning_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF64
 * COL:  0x00E6FF88
 */
using CAiBrainGetArmyIndex_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF6C
 * COL:  0x00E6FF38
 */
using CAiBrainGetFactionIndex_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF74
 * COL:  0x00E6FEE8
 */
using CAiBrainSetCurrentPlan_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF7C
 * COL:  0x00E6FE98
 */
using CAiBrainGetPersonality_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF84
 * COL:  0x00E6FE48
 */
using CAiBrainSetCurrentEnemy_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF8C
 * COL:  0x00E6FDF8
 */
using CAiBrainGetCurrentEnemy_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF94
 * COL:  0x00E6FDA8
 */
using CAiBrainGetUnitBlueprint_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF9C
 * COL:  0x00E6FD58
 */
using CAiBrainGetArmyStat_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFA4
 * COL:  0x00E6FD08
 */
using CAiBrainSetArmyStat_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFAC
 * COL:  0x00E6FCB8
 */
using CAiBrainAddArmyStat_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFB4
 * COL:  0x00E6FC68
 */
using CAiBrainSetGreaterOf_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFBC
 * COL:  0x00E6FC18
 */
using CAiBrainGetBlueprintStat_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFC4
 * COL:  0x00E6FBC8
 */
using CAiBrainGetCurrentUnits_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFCC
 * COL:  0x00E6FB78
 */
using CAiBrainGetListOfUnits_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFD4
 * COL:  0x00E6FB28
 */
using CAiBrainSetArmyStatsTrigger_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFDC
 * COL:  0x00E6FAD8
 */
using CAiBrainRemoveArmyStatsTrigger_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFE4
 * COL:  0x00E6FA88
 */
using CAiBrainGiveResource_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFEC
 * COL:  0x00E6FA38
 */
using CAiBrainGiveStorage_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFF4
 * COL:  0x00E6F9E8
 */
using CAiBrainTakeResource_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFFC
 * COL:  0x00E6F998
 */
using CAiBrainSetResourceSharing_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B004
 * COL:  0x00E6F948
 */
using CAiBrainFindUnit_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B00C
 * COL:  0x00E6F8F8
 */
using CAiBrainFindUpgradeBP_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B014
 * COL:  0x00E6F8A8
 */
using CAiBrainFindUnitToUpgrade_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B01C
 * COL:  0x00E6F858
 */
using CAiBrainDecideWhatToBuild_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B024
 * COL:  0x00E6F808
 */
using CAiBrainGetArmyStartPos_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B02C
 * COL:  0x00E6F7B8
 */
using CAiBrainCreateUnitNearSpot_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B034
 * COL:  0x00E6F768
 */
using CAiBrainCreateResourceBuildingNearest_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B03C
 * COL:  0x00E6F718
 */
using CAiBrainFindPlaceToBuild_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B044
 * COL:  0x00E6F6C8
 */
using CAiBrainCanBuildStructureAt_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B04C
 * COL:  0x00E6F678
 */
using CAiBrainBuildStructure_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B054
 * COL:  0x00E6F628
 */
using CAiBrainNumCurrentlyBuilding_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B05C
 * COL:  0x00E6F5D8
 */
using CAiBrainGetAvailableFactories_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B064
 * COL:  0x00E6F588
 */
using CAiBrainCanBuildPlatoon_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B06C
 * COL:  0x00E6F538
 */
using CAiBrainBuildPlatoon_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B074
 * COL:  0x00E6F4E8
 */
using CAiBrainBuildUnit_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B07C
 * COL:  0x00E6F498
 */
using CAiBrainIsAnyEngineerBuilding_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B084
 * COL:  0x00E6F448
 */
using CAiBrainGetNumPlatoonsWithAI_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B08C
 * COL:  0x00E6F3F8
 */
using CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B094
 * COL:  0x00E6F3A8
 */
using CAiBrainPlatoonExists_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B09C
 * COL:  0x00E6F358
 */
using CAiBrainGetPlatoonsList_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0A4
 * COL:  0x00E6F308
 */
using CAiBrainDisbandPlatoon_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0AC
 * COL:  0x00E6F2B8
 */
using CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0B4
 * COL:  0x00E6F268
 */
using CAiBrainMakePlatoon_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0BC
 * COL:  0x00E6F218
 */
using CAiBrainAssignUnitsToPlatoon_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0C4
 * COL:  0x00E6F1C8
 */
using CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0CC
 * COL:  0x00E6F178
 */
using CAiBrainGetNumUnitsAroundPoint_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0D4
 * COL:  0x00E6F128
 */
using CAiBrainGetUnitsAroundPoint_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0DC
 * COL:  0x00E6F0D8
 */
using CAiBrainFindClosestArmyWithBase_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0E4
 * COL:  0x00E6F088
 */
using CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0EC
 * COL:  0x00E6F038
 */
using CAiBrainGetAttackVectors_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0F4
 * COL:  0x00E6EFE8
 */
using CAiBrainPickBestAttackVector_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0FC
 * COL:  0x00E6EF98
 */
using CAiBrainGetEconomyStored_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B104
 * COL:  0x00E6EF48
 */
using CAiBrainGetEconomyStoredRatio_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B10C
 * COL:  0x00E6EEF8
 */
using CAiBrainGetEconomyIncome_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B114
 * COL:  0x00E6EEA8
 */
using CAiBrainGetEconomyUsage_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B11C
 * COL:  0x00E6EE58
 */
using CAiBrainGetEconomyRequested_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B124
 * COL:  0x00E6EE08
 */
using CAiBrainGetEconomyTrend_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B12C
 * COL:  0x00E6EDB8
 */
using CAiBrainGetMapWaterRatio_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B134
 * COL:  0x00E6ED68
 */
using CAiBrainAssignThreatAtPosition_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B13C
 * COL:  0x00E6ED18
 */
using CAiBrainGetThreatAtPosition_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B144
 * COL:  0x00E6ECC8
 */
using CAiBrainGetThreatBetweenPositions_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B14C
 * COL:  0x00E6EC78
 */
using CAiBrainGetHighestThreatPosition_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B154
 * COL:  0x00E6EC28
 */
using CAiBrainGetThreatsAroundPosition_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B15C
 * COL:  0x00E6EBD8
 */
using CAiBrainCheckBlockingTerrain_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B164
 * COL:  0x00E6EB88
 */
using CAiBrainGetNoRushTicks_LuaFuncDef = ::moho::CScrLuaBinder;
