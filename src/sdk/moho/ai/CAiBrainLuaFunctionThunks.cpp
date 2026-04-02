#include "moho/misc/Stats.h"

#include <cstdlib>
#include <cstring>

#include "moho/lua/CScrLuaInitForm.h"

namespace moho
{
  // Underlying Lua function-definition publishers referenced by this thunk pack.
  CScrLuaInitForm* func_CAiBrainIsOpponentAIRunning_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetArmyIndex_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetFactionIndex_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainSetCurrentPlan_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetPersonality_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainSetCurrentEnemy_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetCurrentEnemy_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetUnitBlueprint_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetArmyStat_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainSetArmyStat_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainAddArmyStat_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainSetGreaterOf_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetBlueprintStat_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetCurrentUnits_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetListOfUnits_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainSetArmyStatsTrigger_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGiveResource_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGiveStorage_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainTakeResource_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainSetResourceSharing_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainFindUnit_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainFindUpgradeBP_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainFindUnitToUpgrade_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainDecideWhatToBuild_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetArmyStartPos_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainCreateUnitNearSpot_LuaFuncDef();
  void func_CAiBrainCreateResourceBuildingNearest_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainFindPlaceToBuild_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainCanBuildStructureAt_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainBuildStructure_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainNumCurrentlyBuilding_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetAvailableFactories_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainCanBuildPlatoon_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainBuildPlatoon_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainBuildUnit_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainIsAnyEngineerBuilding_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainPlatoonExists_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetPlatoonsList_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainDisbandPlatoon_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainMakePlatoon_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainAssignUnitsToPlatoon_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetUnitsAroundPoint_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainFindClosestArmyWithBase_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetAttackVectors_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainPickBestAttackVector_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetEconomyStored_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetEconomyStoredRatio_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetEconomyIncome_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetEconomyUsage_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetEconomyRequested_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetEconomyTrend_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetMapWaterRatio_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainAssignThreatAtPosition_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetThreatAtPosition_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetThreatBetweenPositions_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetHighestThreatPosition_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetThreatsAroundPosition_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainCheckBlockingTerrain_LuaFuncDef();
  CScrLuaInitForm* func_CAiBrainGetNoRushTicks_LuaFuncDef();

  CScrLuaInitForm* register_sim_SimInits_mForms_resourceDepositFactoryAnchor();
  int register_AiBrainPrimaryEngineStatsCleanupAtExit();
  int register_AiBrainEngineStatsCleanupAtExit();
} // namespace moho

namespace
{
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_ResourceDepositStartup = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_ResourceDepositStartup = nullptr;

  // Maps the cleanup slot used by FUN_00BF6440 (`dword_10AE09C`).
  moho::EngineStats* gAiBrainPrimaryEngineStatsCleanupSlot = nullptr;

  // Maps the cleanup slot used by FUN_00BF64F0 (`dword_10AE298`).
  // Ownership is not fully recovered yet, so keep it isolated from the
  // primary `moho::sEngineStats` singleton lane.
  moho::EngineStats* gAiBrainStartupEngineStatsCleanupSlot = nullptr;

  [[nodiscard]] moho::CScrLuaInitFormSet* FindLuaInitFormSetByName(const char* const setName) noexcept
  {
    for (moho::CScrLuaInitFormSet* set = moho::CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, setName) == 0) {
        return set;
      }
    }

    return nullptr;
  }

  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardAiBrainLuaRegistrationThunk() noexcept
  {
    return Target();
  }

  void CleanupEngineStatsSingletonAtProcessExit()
  {
    moho::EngineStats* const engineStats = gAiBrainStartupEngineStatsCleanupSlot;
    if (!engineStats) {
      return;
    }

    engineStats->~EngineStats();
    ::operator delete(engineStats);
  }

  void CleanupPrimaryEngineStatsSingletonAtProcessExit()
  {
    moho::EngineStats* const engineStats = gAiBrainPrimaryEngineStatsCleanupSlot;
    if (!engineStats) {
      return;
    }

    engineStats->~EngineStats();
    ::operator delete(engineStats);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BCB740 (FUN_00BCB740, register_CAiBrainIsOpponentAIRunning_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainIsOpponentAIRunning_LuaFuncDef` to `func_CAiBrainIsOpponentAIRunning_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainIsOpponentAIRunning_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainIsOpponentAIRunning_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB750 (FUN_00BCB750, j_func_CAiBrainGetArmyIndex_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainGetArmyIndex_LuaFuncDef` to `func_CAiBrainGetArmyIndex_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainGetArmyIndex_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetArmyIndex_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB760 (FUN_00BCB760, register_CAiBrainGetFactionIndex_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetFactionIndex_LuaFuncDef` to `func_CAiBrainGetFactionIndex_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetFactionIndex_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetFactionIndex_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB770 (FUN_00BCB770, register_CAiBrainSetCurrentPlan_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainSetCurrentPlan_LuaFuncDef` to `func_CAiBrainSetCurrentPlan_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainSetCurrentPlan_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainSetCurrentPlan_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB780 (FUN_00BCB780, j_func_CAiBrainGetPersonality_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainGetPersonality_LuaFuncDef` to `func_CAiBrainGetPersonality_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainGetPersonality_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetPersonality_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB790 (FUN_00BCB790, register_CAiBrainSetCurrentEnemy_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainSetCurrentEnemy_LuaFuncDef` to `func_CAiBrainSetCurrentEnemy_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainSetCurrentEnemy_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainSetCurrentEnemy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB7A0 (FUN_00BCB7A0, register_CAiBrainGetCurrentEnemy_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetCurrentEnemy_LuaFuncDef` to `func_CAiBrainGetCurrentEnemy_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetCurrentEnemy_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetCurrentEnemy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB7B0 (FUN_00BCB7B0, register_CAiBrainGetUnitBlueprint_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetUnitBlueprint_LuaFuncDef` to `func_CAiBrainGetUnitBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetUnitBlueprint_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetUnitBlueprint_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB7C0 (FUN_00BCB7C0, j_func_CAiBrainGetArmyStat_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainGetArmyStat_LuaFuncDef` to `func_CAiBrainGetArmyStat_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainGetArmyStat_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetArmyStat_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB7D0 (FUN_00BCB7D0, register_CAiBrainSetArmyStat_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainSetArmyStat_LuaFuncDef` to `func_CAiBrainSetArmyStat_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainSetArmyStat_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainSetArmyStat_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB7E0 (FUN_00BCB7E0, j_func_CAiBrainAddArmyStat_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainAddArmyStat_LuaFuncDef` to `func_CAiBrainAddArmyStat_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainAddArmyStat_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainAddArmyStat_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB7F0 (FUN_00BCB7F0, register_CAiBrainSetGreaterOf_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainSetGreaterOf_LuaFuncDef` to `func_CAiBrainSetGreaterOf_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainSetGreaterOf_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainSetGreaterOf_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB800 (FUN_00BCB800, register_CAiBrainGetBlueprintStat_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetBlueprintStat_LuaFuncDef` to `func_CAiBrainGetBlueprintStat_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetBlueprintStat_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetBlueprintStat_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB810 (FUN_00BCB810, register_CAiBrainGetCurrentUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetCurrentUnits_LuaFuncDef` to `func_CAiBrainGetCurrentUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetCurrentUnits_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetCurrentUnits_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB820 (FUN_00BCB820, register_CAiBrainGetListOfUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetListOfUnits_LuaFuncDef` to `func_CAiBrainGetListOfUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetListOfUnits_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetListOfUnits_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB830 (FUN_00BCB830, register_CAiBrainSetArmyStatsTrigger_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainSetArmyStatsTrigger_LuaFuncDef` to `func_CAiBrainSetArmyStatsTrigger_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainSetArmyStatsTrigger_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainSetArmyStatsTrigger_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB840 (FUN_00BCB840, j_func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef` to `func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB850 (FUN_00BCB850, register_CAiBrainGiveResource_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGiveResource_LuaFuncDef` to `func_CAiBrainGiveResource_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGiveResource_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGiveResource_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB860 (FUN_00BCB860, register_CAiBrainGiveStorage_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGiveStorage_LuaFuncDef` to `func_CAiBrainGiveStorage_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGiveStorage_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGiveStorage_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB870 (FUN_00BCB870, register_CAiBrainTakeResource_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainTakeResource_LuaFuncDef` to `func_CAiBrainTakeResource_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainTakeResource_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainTakeResource_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB880 (FUN_00BCB880, register_CAiBrainSetResourceSharing_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainSetResourceSharing_LuaFuncDef` to `func_CAiBrainSetResourceSharing_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainSetResourceSharing_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainSetResourceSharing_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB890 (FUN_00BCB890, register_CAiBrainFindUnit_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainFindUnit_LuaFuncDef` to `func_CAiBrainFindUnit_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainFindUnit_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainFindUnit_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB8A0 (FUN_00BCB8A0, j_func_CAiBrainFindUpgradeBP_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainFindUpgradeBP_LuaFuncDef` to `func_CAiBrainFindUpgradeBP_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainFindUpgradeBP_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainFindUpgradeBP_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB8B0 (FUN_00BCB8B0, register_CAiBrainFindUnitToUpgrade_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainFindUnitToUpgrade_LuaFuncDef` to `func_CAiBrainFindUnitToUpgrade_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainFindUnitToUpgrade_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainFindUnitToUpgrade_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB8C0 (FUN_00BCB8C0, register_CAiBrainDecideWhatToBuild_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainDecideWhatToBuild_LuaFuncDef` to `func_CAiBrainDecideWhatToBuild_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainDecideWhatToBuild_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainDecideWhatToBuild_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB8D0 (FUN_00BCB8D0, register_CAiBrainGetArmyStartPos_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetArmyStartPos_LuaFuncDef` to `func_CAiBrainGetArmyStartPos_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetArmyStartPos_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetArmyStartPos_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB8E0 (FUN_00BCB8E0, register_CAiBrainCreateUnitNearSpot_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainCreateUnitNearSpot_LuaFuncDef` to `func_CAiBrainCreateUnitNearSpot_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainCreateUnitNearSpot_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainCreateUnitNearSpot_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB8F0 (FUN_00BCB8F0, register_CAiBrainCreateResourceBuildingNearest_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainCreateResourceBuildingNearest_LuaFuncDef` to `func_CAiBrainCreateResourceBuildingNearest_LuaFuncDef`.
   */
  void register_CAiBrainCreateResourceBuildingNearest_LuaFuncDef()
  {
    func_CAiBrainCreateResourceBuildingNearest_LuaFuncDef();
  }

  /**
   * Address: 0x00BCB900 (FUN_00BCB900, register_CAiBrainFindPlaceToBuild_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainFindPlaceToBuild_LuaFuncDef` to `func_CAiBrainFindPlaceToBuild_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainFindPlaceToBuild_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainFindPlaceToBuild_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB910 (FUN_00BCB910, j_func_CAiBrainCanBuildStructureAt_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainCanBuildStructureAt_LuaFuncDef` to `func_CAiBrainCanBuildStructureAt_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainCanBuildStructureAt_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainCanBuildStructureAt_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB920 (FUN_00BCB920, register_CAiBrainBuildStructure_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainBuildStructure_LuaFuncDef` to `func_CAiBrainBuildStructure_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainBuildStructure_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainBuildStructure_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB930 (FUN_00BCB930, j_func_CAiBrainNumCurrentlyBuilding_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainNumCurrentlyBuilding_LuaFuncDef` to `func_CAiBrainNumCurrentlyBuilding_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainNumCurrentlyBuilding_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainNumCurrentlyBuilding_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB940 (FUN_00BCB940, register_CAiBrainGetAvailableFactories_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetAvailableFactories_LuaFuncDef` to `func_CAiBrainGetAvailableFactories_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetAvailableFactories_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetAvailableFactories_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB950 (FUN_00BCB950, register_CAiBrainCanBuildPlatoon_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainCanBuildPlatoon_LuaFuncDef` to `func_CAiBrainCanBuildPlatoon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainCanBuildPlatoon_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainCanBuildPlatoon_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB960 (FUN_00BCB960, register_CAiBrainBuildPlatoon_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainBuildPlatoon_LuaFuncDef` to `func_CAiBrainBuildPlatoon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainBuildPlatoon_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainBuildPlatoon_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB970 (FUN_00BCB970, register_CAiBrainBuildUnit_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainBuildUnit_LuaFuncDef` to `func_CAiBrainBuildUnit_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainBuildUnit_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainBuildUnit_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB980 (FUN_00BCB980, register_CAiBrainIsAnyEngineerBuilding_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainIsAnyEngineerBuilding_LuaFuncDef` to `func_CAiBrainIsAnyEngineerBuilding_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainIsAnyEngineerBuilding_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainIsAnyEngineerBuilding_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB990 (FUN_00BCB990, j_func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef` to `func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB9A0 (FUN_00BCB9A0, register_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef` to `func_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB9B0 (FUN_00BCB9B0, register_CAiBrainPlatoonExists_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainPlatoonExists_LuaFuncDef` to `func_CAiBrainPlatoonExists_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainPlatoonExists_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainPlatoonExists_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB9C0 (FUN_00BCB9C0, register_CAiBrainGetPlatoonsList_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetPlatoonsList_LuaFuncDef` to `func_CAiBrainGetPlatoonsList_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetPlatoonsList_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetPlatoonsList_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB9D0 (FUN_00BCB9D0, register_CAiBrainDisbandPlatoon_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainDisbandPlatoon_LuaFuncDef` to `func_CAiBrainDisbandPlatoon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainDisbandPlatoon_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainDisbandPlatoon_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB9E0 (FUN_00BCB9E0, register_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef` to `func_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB9F0 (FUN_00BCB9F0, j_func_CAiBrainMakePlatoon_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainMakePlatoon_LuaFuncDef` to `func_CAiBrainMakePlatoon_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainMakePlatoon_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainMakePlatoon_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBA00 (FUN_00BCBA00, register_CAiBrainAssignUnitsToPlatoon_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainAssignUnitsToPlatoon_LuaFuncDef` to `func_CAiBrainAssignUnitsToPlatoon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainAssignUnitsToPlatoon_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainAssignUnitsToPlatoon_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBA10 (FUN_00BCBA10, register_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef` to `func_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBA20 (FUN_00BCBA20, register_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef` to `func_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBA30 (FUN_00BCBA30, register_CAiBrainGetUnitsAroundPoint_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetUnitsAroundPoint_LuaFuncDef` to `func_CAiBrainGetUnitsAroundPoint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetUnitsAroundPoint_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetUnitsAroundPoint_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBA40 (FUN_00BCBA40, register_CAiBrainFindClosestArmyWithBase_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainFindClosestArmyWithBase_LuaFuncDef` to `func_CAiBrainFindClosestArmyWithBase_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainFindClosestArmyWithBase_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainFindClosestArmyWithBase_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBA50 (FUN_00BCBA50, register_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef` to `func_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBA60 (FUN_00BCBA60, register_CAiBrainGetAttackVectors_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetAttackVectors_LuaFuncDef` to `func_CAiBrainGetAttackVectors_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetAttackVectors_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetAttackVectors_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBA70 (FUN_00BCBA70, register_CAiBrainPickBestAttackVector_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainPickBestAttackVector_LuaFuncDef` to `func_CAiBrainPickBestAttackVector_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainPickBestAttackVector_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainPickBestAttackVector_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBA80 (FUN_00BCBA80, j_func_CAiBrainGetEconomyStored_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainGetEconomyStored_LuaFuncDef` to `func_CAiBrainGetEconomyStored_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainGetEconomyStored_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetEconomyStored_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBA90 (FUN_00BCBA90, register_CAiBrainGetEconomyStoredRatio_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetEconomyStoredRatio_LuaFuncDef` to `func_CAiBrainGetEconomyStoredRatio_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetEconomyStoredRatio_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetEconomyStoredRatio_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBAA0 (FUN_00BCBAA0, register_CAiBrainGetEconomyIncome_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetEconomyIncome_LuaFuncDef` to `func_CAiBrainGetEconomyIncome_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetEconomyIncome_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetEconomyIncome_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBAB0 (FUN_00BCBAB0, j_func_CAiBrainGetEconomyUsage_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainGetEconomyUsage_LuaFuncDef` to `func_CAiBrainGetEconomyUsage_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainGetEconomyUsage_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetEconomyUsage_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBAC0 (FUN_00BCBAC0, register_CAiBrainGetEconomyRequested_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetEconomyRequested_LuaFuncDef` to `func_CAiBrainGetEconomyRequested_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetEconomyRequested_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetEconomyRequested_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBAD0 (FUN_00BCBAD0, register_CAiBrainGetEconomyTrend_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetEconomyTrend_LuaFuncDef` to `func_CAiBrainGetEconomyTrend_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetEconomyTrend_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetEconomyTrend_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBAE0 (FUN_00BCBAE0, register_CAiBrainGetMapWaterRatio_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetMapWaterRatio_LuaFuncDef` to `func_CAiBrainGetMapWaterRatio_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetMapWaterRatio_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetMapWaterRatio_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBAF0 (FUN_00BCBAF0, register_CAiBrainAssignThreatAtPosition_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainAssignThreatAtPosition_LuaFuncDef` to `func_CAiBrainAssignThreatAtPosition_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainAssignThreatAtPosition_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainAssignThreatAtPosition_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBB00 (FUN_00BCBB00, register_CAiBrainGetThreatAtPosition_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetThreatAtPosition_LuaFuncDef` to `func_CAiBrainGetThreatAtPosition_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetThreatAtPosition_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetThreatAtPosition_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBB10 (FUN_00BCBB10, register_CAiBrainGetThreatBetweenPositions_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetThreatBetweenPositions_LuaFuncDef` to `func_CAiBrainGetThreatBetweenPositions_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetThreatBetweenPositions_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetThreatBetweenPositions_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBB20 (FUN_00BCBB20, register_CAiBrainGetHighestThreatPosition_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetHighestThreatPosition_LuaFuncDef` to `func_CAiBrainGetHighestThreatPosition_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetHighestThreatPosition_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetHighestThreatPosition_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBB30 (FUN_00BCBB30, register_CAiBrainGetThreatsAroundPosition_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetThreatsAroundPosition_LuaFuncDef` to `func_CAiBrainGetThreatsAroundPosition_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetThreatsAroundPosition_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetThreatsAroundPosition_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBB40 (FUN_00BCBB40, j_func_CAiBrainCheckBlockingTerrain_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CAiBrainCheckBlockingTerrain_LuaFuncDef` to `func_CAiBrainCheckBlockingTerrain_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiBrainCheckBlockingTerrain_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainCheckBlockingTerrain_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCBB50 (FUN_00BCBB50, register_CAiBrainGetNoRushTicks_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CAiBrainGetNoRushTicks_LuaFuncDef` to `func_CAiBrainGetNoRushTicks_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiBrainGetNoRushTicks_LuaFuncDef()
  {
    return ForwardAiBrainLuaRegistrationThunk<&func_CAiBrainGetNoRushTicks_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCB6C0 (FUN_00BCB6C0, sub_BCB6C0)
   *
   * What it does:
   * Saves current `sim` Lua-init form chain head and relinks it to the
   * recovered resource-deposit startup anchor lane.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_resourceDepositFactoryAnchor()
  {
    CScrLuaInitFormSet* const simSet = FindLuaInitFormSetByName("sim");
    if (simSet == nullptr) {
      gRecoveredSimLuaInitFormPrev_ResourceDepositStartup = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gRecoveredSimLuaInitFormPrev_ResourceDepositStartup = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gRecoveredSimLuaInitFormAnchor_ResourceDepositStartup);
    return result;
  }

  /**
   * Address: 0x00BCB4D0 (FUN_00BCB4D0, sub_BCB4D0)
   *
   * What it does:
   * Registers process-exit cleanup for the primary AI-brain startup stats slot.
   */
  int register_AiBrainPrimaryEngineStatsCleanupAtExit()
  {
    return std::atexit(&CleanupPrimaryEngineStatsSingletonAtProcessExit);
  }

  /**
   * Address: 0x00BCBB60 (FUN_00BCBB60, sub_BCBB60)
   *
   * What it does:
   * Registers the recovered engine-stats cleanup callback for process exit.
   */
  int register_AiBrainEngineStatsCleanupAtExit()
  {
    return std::atexit(&CleanupEngineStatsSingletonAtProcessExit);
  }
} // namespace moho

namespace
{
  struct CAiBrainLuaFunctionThunksBootstrap
  {
    CAiBrainLuaFunctionThunksBootstrap()
    {
      (void)moho::register_sim_SimInits_mForms_resourceDepositFactoryAnchor();
      (void)moho::register_CAiBrainIsOpponentAIRunning_LuaFuncDef();
      (void)moho::j_func_CAiBrainGetArmyIndex_LuaFuncDef();
      (void)moho::register_CAiBrainGetFactionIndex_LuaFuncDef();
      (void)moho::register_CAiBrainSetCurrentPlan_LuaFuncDef();
      (void)moho::j_func_CAiBrainGetPersonality_LuaFuncDef();
      (void)moho::register_CAiBrainSetCurrentEnemy_LuaFuncDef();
      (void)moho::register_CAiBrainGetCurrentEnemy_LuaFuncDef();
      (void)moho::register_CAiBrainGetUnitBlueprint_LuaFuncDef();
      (void)moho::j_func_CAiBrainGetArmyStat_LuaFuncDef();
      (void)moho::register_CAiBrainSetArmyStat_LuaFuncDef();
      (void)moho::j_func_CAiBrainAddArmyStat_LuaFuncDef();
      (void)moho::register_CAiBrainSetGreaterOf_LuaFuncDef();
      (void)moho::register_CAiBrainGetBlueprintStat_LuaFuncDef();
      (void)moho::register_CAiBrainGetCurrentUnits_LuaFuncDef();
      (void)moho::register_CAiBrainGetListOfUnits_LuaFuncDef();
      (void)moho::register_CAiBrainSetArmyStatsTrigger_LuaFuncDef();
      (void)moho::j_func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef();
      (void)moho::register_CAiBrainGiveResource_LuaFuncDef();
      (void)moho::register_CAiBrainGiveStorage_LuaFuncDef();
      (void)moho::register_CAiBrainTakeResource_LuaFuncDef();
      (void)moho::register_CAiBrainSetResourceSharing_LuaFuncDef();
      (void)moho::register_CAiBrainFindUnit_LuaFuncDef();
      (void)moho::j_func_CAiBrainFindUpgradeBP_LuaFuncDef();
      (void)moho::register_CAiBrainFindUnitToUpgrade_LuaFuncDef();
      (void)moho::register_CAiBrainDecideWhatToBuild_LuaFuncDef();
      (void)moho::register_CAiBrainGetArmyStartPos_LuaFuncDef();
      (void)moho::register_CAiBrainCreateUnitNearSpot_LuaFuncDef();
      (void)moho::register_CAiBrainCreateResourceBuildingNearest_LuaFuncDef();
      (void)moho::register_CAiBrainFindPlaceToBuild_LuaFuncDef();
      (void)moho::j_func_CAiBrainCanBuildStructureAt_LuaFuncDef();
      (void)moho::register_CAiBrainBuildStructure_LuaFuncDef();
      (void)moho::j_func_CAiBrainNumCurrentlyBuilding_LuaFuncDef();
      (void)moho::register_CAiBrainGetAvailableFactories_LuaFuncDef();
      (void)moho::register_CAiBrainCanBuildPlatoon_LuaFuncDef();
      (void)moho::register_CAiBrainBuildPlatoon_LuaFuncDef();
      (void)moho::register_CAiBrainBuildUnit_LuaFuncDef();
      (void)moho::register_CAiBrainIsAnyEngineerBuilding_LuaFuncDef();
      (void)moho::j_func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef();
      (void)moho::register_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef();
      (void)moho::register_CAiBrainPlatoonExists_LuaFuncDef();
      (void)moho::register_CAiBrainGetPlatoonsList_LuaFuncDef();
      (void)moho::register_CAiBrainDisbandPlatoon_LuaFuncDef();
      (void)moho::register_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef();
      (void)moho::j_func_CAiBrainMakePlatoon_LuaFuncDef();
      (void)moho::register_CAiBrainAssignUnitsToPlatoon_LuaFuncDef();
      (void)moho::register_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef();
      (void)moho::register_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef();
      (void)moho::register_CAiBrainGetUnitsAroundPoint_LuaFuncDef();
      (void)moho::register_CAiBrainFindClosestArmyWithBase_LuaFuncDef();
      (void)moho::register_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef();
      (void)moho::register_CAiBrainGetAttackVectors_LuaFuncDef();
      (void)moho::register_CAiBrainPickBestAttackVector_LuaFuncDef();
      (void)moho::j_func_CAiBrainGetEconomyStored_LuaFuncDef();
      (void)moho::register_CAiBrainGetEconomyStoredRatio_LuaFuncDef();
      (void)moho::register_CAiBrainGetEconomyIncome_LuaFuncDef();
      (void)moho::j_func_CAiBrainGetEconomyUsage_LuaFuncDef();
      (void)moho::register_CAiBrainGetEconomyRequested_LuaFuncDef();
      (void)moho::register_CAiBrainGetEconomyTrend_LuaFuncDef();
      (void)moho::register_CAiBrainGetMapWaterRatio_LuaFuncDef();
      (void)moho::register_CAiBrainAssignThreatAtPosition_LuaFuncDef();
      (void)moho::register_CAiBrainGetThreatAtPosition_LuaFuncDef();
      (void)moho::register_CAiBrainGetThreatBetweenPositions_LuaFuncDef();
      (void)moho::register_CAiBrainGetHighestThreatPosition_LuaFuncDef();
      (void)moho::register_CAiBrainGetThreatsAroundPosition_LuaFuncDef();
      (void)moho::j_func_CAiBrainCheckBlockingTerrain_LuaFuncDef();
      (void)moho::register_CAiBrainGetNoRushTicks_LuaFuncDef();
      (void)moho::register_AiBrainPrimaryEngineStatsCleanupAtExit();
      (void)moho::register_AiBrainEngineStatsCleanupAtExit();
    }
  };

  [[maybe_unused]] CAiBrainLuaFunctionThunksBootstrap gCAiBrainLuaFunctionThunksBootstrap;
} // namespace
