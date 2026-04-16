#pragma once

namespace moho
{
  class CSimConVarBase;

  /**
   * Address: 0x00BD3890 (FUN_00BD3890, register_SallyShears_ConAliasDef)
   *
   * What it does:
   * Registers the `SallyShears` console alias and installs startup cleanup.
   */
  void register_SallyShears_ConAliasDef();

  /**
   * Address: 0x00BD38C0 (FUN_00BD38C0, register_SallyShears_SimConFuncDef)
   *
   * What it does:
   * Registers the `SallyShears` sim command callback and installs startup
   * cleanup.
   */
  void register_SallyShears_SimConFuncDef();

  /**
   * Address: 0x00BD3900 (FUN_00BD3900, register_BlingBling_ConAlias)
   *
   * What it does:
   * Registers the `BlingBling` console alias and installs startup cleanup.
   */
  void register_BlingBling_ConAlias();

  /**
   * Address: 0x00BD3930 (FUN_00BD3930, register_BlingBling_SimConFunc)
   *
   * What it does:
   * Registers the `BlingBling` sim command callback and installs startup
   * cleanup.
   */
  void register_BlingBling_SimConFunc();

  /**
   * Address: 0x00BD3970 (FUN_00BD3970, register_ZeroExtraStorage_ConAliasDef)
   *
   * What it does:
   * Registers the `ZeroExtraStorage` console alias and installs startup
   * cleanup.
   */
  void register_ZeroExtraStorage_ConAliasDef();

  /**
   * Address: 0x00BD39A0 (FUN_00BD39A0, func_ZeroExtraStorage_SimConFuncDef)
   *
   * What it does:
   * Registers the `ZeroExtraStorage` sim command callback and installs startup
   * cleanup.
   */
  void register_ZeroExtraStorage_SimConFuncDef();

  /**
   * Address: 0x00BD39E0 (FUN_00BD39E0, register_DamageUnit_ConAlias)
   *
   * What it does:
   * Registers the `DamageUnit` console alias and installs startup cleanup.
   */
  void register_DamageUnit_ConAlias();

  /**
   * Address: 0x00BD3A50 (FUN_00BD3A50, register_AddImpulse_ConAliasDef)
   *
   * What it does:
   * Registers the `AddImpulse` console alias and installs startup cleanup.
   */
  void register_AddImpulse_ConAliasDef();

  /**
   * Address: 0x00BD3A80 (FUN_00BD3A80, register_AddImpulse_SimConFuncDef)
   *
   * What it does:
   * Registers the `AddImpulse` sim command callback and installs startup
   * cleanup.
   */
  void register_AddImpulse_SimConFuncDef();

  /**
   * Address: 0x00BCE6D0 (FUN_00BCE6D0, register_WeaponTerrainBlockageTest_ConAliasDef)
   *
   * What it does:
   * Registers the `WeaponTerrainBlockageTest` console alias and installs
   * startup cleanup.
   */
  void register_WeaponTerrainBlockageTest_ConAliasDef();

  /**
   * Address: 0x00BCE700 (FUN_00BCE700, register_WeaponTerrainBlockageTest_SimConVarDef)
   *
   * What it does:
   * Registers the `WeaponTerrainBlockageTest` sim convar and installs startup
   * cleanup.
   */
  void register_WeaponTerrainBlockageTest_SimConVarDef();

  /**
   * Address: 0x00BD1F60 (FUN_00BD1F60, register_NeedRefuelThresholdRatio_ConAliasDef)
   *
   * What it does:
   * Registers the `NeedRefuelThresholdRatio` console alias and installs
   * startup cleanup.
   */
  void register_NeedRefuelThresholdRatio_ConAliasDef();

  /**
   * Address: 0x00BD1F90 (FUN_00BD1F90, register_NeedRefuelThresholdRatio_SimConVarDef)
   *
   * What it does:
   * Registers the `NeedRefuelThresholdRatio` sim convar and installs startup
   * cleanup.
   */
  void register_NeedRefuelThresholdRatio_SimConVarDef();

  /**
   * Address: 0x00BD1FE0 (FUN_00BD1FE0, register_NeedRepairThresholdRatio_ConAliasDef)
   *
   * What it does:
   * Registers the `NeedRepairThresholdRatio` console alias and installs
   * startup cleanup.
   */
  void register_NeedRepairThresholdRatio_ConAliasDef();

  /**
   * Address: 0x00BD2010 (FUN_00BD2010, register_NeedRepairThresholdRatio_SimConVarDef)
   *
   * What it does:
   * Registers the `NeedRepairThresholdRatio` sim convar and installs startup
   * cleanup.
   */
  void register_NeedRepairThresholdRatio_SimConVarDef();

  /** Address: 0x00BFB470 (FUN_00BFB470, sub_BFB470) */
  void cleanup_SallyShears_ConAlias();

  /** Address: 0x00BFB4C0 (FUN_00BFB4C0, sub_BFB4C0) */
  void cleanup_SallyShears_SimConFunc();

  /** Address: 0x00BFB4D0 (FUN_00BFB4D0, sub_BFB4D0) */
  void cleanup_BlingBling_ConAlias();

  /** Address: 0x00BFB520 (FUN_00BFB520, sub_BFB520) */
  void cleanup_BlingBling_SimConFunc();

  /** Address: 0x00BFB530 (FUN_00BFB530, sub_BFB530) */
  void cleanup_ZeroExtraStorage_ConAlias();

  /** Address: 0x00BFB580 (FUN_00BFB580, sub_BFB580) */
  void cleanup_ZeroExtraStorage_SimConFunc();

  /** Address: 0x00BFB590 (FUN_00BFB590, sub_BFB590) */
  void cleanup_DamageUnit_ConAlias();

  /** Address: 0x00BFB5F0 (FUN_00BFB5F0, sub_BFB5F0) */
  void cleanup_AddImpulse_ConAlias();

  /** Address: 0x00BFB640 (FUN_00BFB640, sub_BFB640) */
  void cleanup_AddImpulse_SimConFunc();

  /**
   * Address: 0x00BFA720 (FUN_00BFA720, cleanup_NeedRefuelThresholdRatio_ConAlias)
   *
   * What it does:
   * Tears down the startup-owned `NeedRefuelThresholdRatio` alias storage.
   */
  void cleanup_NeedRefuelThresholdRatio_ConAlias();

  /**
   * Address: 0x00BFA770 (FUN_00BFA770, cleanup_NeedRefuelThresholdRatio_SimConVar)
   *
   * What it does:
   * Destroys the startup-owned `NeedRefuelThresholdRatio` sim-convar storage.
   */
  void cleanup_NeedRefuelThresholdRatio_SimConVar();

  /**
   * Address: 0x00BFA780 (FUN_00BFA780, cleanup_NeedRepairThresholdRatio_ConAlias)
   *
   * What it does:
   * Tears down the startup-owned `NeedRepairThresholdRatio` alias storage.
   */
  void cleanup_NeedRepairThresholdRatio_ConAlias();

  /**
   * Address: 0x00BFA7D0 (FUN_00BFA7D0, cleanup_NeedRepairThresholdRatio_SimConVar)
   *
   * What it does:
   * Destroys the startup-owned `NeedRepairThresholdRatio` sim-convar storage.
   */
  void cleanup_NeedRepairThresholdRatio_SimConVar();

  /**
   * Address: 0x00BD3D80 (FUN_00BD3D80, register_dbg_ConAlias)
   *
   * What it does:
   * Registers the startup-owned `dbg` console alias.
   */
  void register_dbg_ConAlias();

  /**
   * Address: 0x00BD3DB0 (FUN_00BD3DB0, register_dbg_SimConFunc)
   *
   * What it does:
   * Registers the startup-owned `dbg` sim command callback.
   */
  void register_dbg_SimConFunc();

  /**
   * Address: 0x00BFB7D0 (FUN_00BFB7D0, cleanup_dbg_ConAlias)
   *
   * What it does:
   * Tears down the startup-owned `dbg` alias payload and unregisters the
   * command binding.
   */
  void cleanup_dbg_ConAlias();

  /**
   * Address: 0x00BFB820 (FUN_00BFB820, cleanup_dbg_SimConFunc)
   *
   * What it does:
   * Destroys the startup-owned `dbg` sim command callback object.
   */
  void cleanup_dbg_SimConFunc();

  /**
   * Address: 0x00BD4E80 (FUN_00BD4E80, register_NoDamage_ConAliasDef)
   *
   * What it does:
   * Registers the `NoDamage` console alias and installs startup cleanup.
   */
  void register_NoDamage_ConAliasDef();

  /**
   * Address: 0x00BCB050 (FUN_00BCB050, register_AI_RunOpponentAI_ConAlias)
   *
   * What it does:
   * Registers the `AI_RunOpponentAI` console alias and installs startup
   * cleanup.
   */
  void register_AI_RunOpponentAI_ConAlias();

  /**
   * Address: 0x00BCB080 (FUN_00BCB080, register_AI_RunOpponentAI_SimConVarDef)
   *
   * What it does:
   * Registers `AI_RunOpponentAI` sim convar and installs startup cleanup.
   */
  void register_AI_RunOpponentAI_SimConVarDef();

  /**
   * What it does:
   * Returns the recovered `AI_RunOpponentAI` sim-convar definition object.
   */
  [[nodiscard]] CSimConVarBase* GetAI_RunOpponentAI_SimConVarDef();

  /**
   * Address: 0x00BCB0D0 (FUN_00BCB0D0, register_AI_DebugArmyIndex_ConAlias)
   *
   * What it does:
   * Registers the `AI_DebugArmyIndex` console alias and installs startup
   * cleanup.
   */
  void register_AI_DebugArmyIndex_ConAlias();

  /**
   * Address: 0x00BCB100 (FUN_00BCB100, register_AI_DebugArmyIndex_SimConDef)
   *
   * What it does:
   * Registers `AI_DebugArmyIndex` sim convar and installs startup cleanup.
   */
  void register_AI_DebugArmyIndex_SimConDef();

  /**
   * Address: 0x00BCB150 (FUN_00BCB150, register_AI_RenderDebugAttackVectors_ConAlias)
   *
   * What it does:
   * Registers the `AI_RenderDebugAttackVectors` console alias and installs
   * startup cleanup.
   */
  void register_AI_RenderDebugAttackVectors_ConAlias();

  /**
   * Address: 0x00BCB180 (FUN_00BCB180, register_AI_RenderDebugAttackVectors_SimConVarDef)
   *
   * What it does:
   * Registers `AI_RenderDebugAttackVectors` sim convar and installs startup
   * cleanup.
   */
  void register_AI_RenderDebugAttackVectors_SimConVarDef();

  /**
   * Address: 0x00BCB1D0 (FUN_00BCB1D0, register_AI_RenderDebugPlayableRect_ConAlias)
   *
   * What it does:
   * Registers the `AI_RenderDebugPlayableRect` console alias and installs
   * startup cleanup.
   */
  void register_AI_RenderDebugPlayableRect_ConAlias();

  /**
   * Address: 0x00BCB200 (FUN_00BCB200, register_AI_RenderDebugPlayableRect_SimConVarDef)
   *
   * What it does:
   * Registers `AI_RenderDebugPlayableRect` sim convar and installs startup
   * cleanup.
   */
  void register_AI_RenderDebugPlayableRect_SimConVarDef();

  /**
   * Address: 0x00BCB250 (FUN_00BCB250, register_AI_DebugCollision_ConAlias)
   *
   * What it does:
   * Registers the `AI_DebugCollision` console alias and installs startup
   * cleanup.
   */
  void register_AI_DebugCollision_ConAlias();

  /**
   * Address: 0x00BCB280 (FUN_00BCB280, register_AI_DebugCollision_SimConVarDef)
   *
   * What it does:
   * Registers `AI_DebugCollision` sim convar and installs startup cleanup.
   */
  void register_AI_DebugCollision_SimConVarDef();

  /**
   * Address: 0x00BCB2D0 (FUN_00BCB2D0, register_AI_DebugIgnorePlayableRect_ConAlias)
   *
   * What it does:
   * Registers the `AI_DebugIgnorePlayableRect` console alias and installs
   * startup cleanup.
   */
  void register_AI_DebugIgnorePlayableRect_ConAlias();

  /**
   * Address: 0x00BCB300 (FUN_00BCB300, register_AI_DebugIgnorePlayableRect_SimConVarDef)
   *
   * What it does:
   * Registers `AI_DebugIgnorePlayableRect` sim convar and installs startup
   * cleanup.
   */
  void register_AI_DebugIgnorePlayableRect_SimConVarDef();

  /**
   * Address: 0x00BCF710 (FUN_00BCF710, register_ai_InstaBuild_ConAliasDef)
   *
   * What it does:
   * Registers the `ai_InstaBuild` console alias and installs startup cleanup.
   */
  void register_ai_InstaBuild_ConAliasDef();

  /**
   * Address: 0x00BCF740 (FUN_00BCF740, register_ai_InstaBuild_SimConVarDef)
   *
   * What it does:
   * Registers the `ai_InstaBuild` sim convar definition and installs startup
   * cleanup.
   */
  void register_ai_InstaBuild_SimConVarDef();

  /**
   * Address: 0x00BCF790 (FUN_00BCF790, register_ai_FreeBuild_ConAliasDef)
   *
   * What it does:
   * Registers the `ai_FreeBuild` console alias and installs startup cleanup.
   */
  void register_ai_FreeBuild_ConAliasDef();

  /**
   * Address: 0x00BCF7C0 (FUN_00BCF7C0, register_ai_FreeBuild_SimConVarDef)
   *
   * What it does:
   * Registers the `ai_FreeBuild` sim convar definition and installs startup
   * cleanup.
   */
  void register_ai_FreeBuild_SimConVarDef();

  /**
   * Address: 0x00BCE3A0 (FUN_00BCE3A0, register_ai_SteeringAirTolerance_ConAliasDef)
   *
   * What it does:
   * Registers `ai_SteeringAirTolerance` console alias and installs startup
   * cleanup.
   */
  void register_ai_SteeringAirTolerance_ConAliasDef();

  /**
   * Address: 0x00BCE3D0 (FUN_00BCE3D0, register_ai_SteeringAirTolerance_SimConVarDef)
   *
   * What it does:
   * Registers `ai_SteeringAirTolerance` sim convar and installs startup
   * cleanup.
   */
  void register_ai_SteeringAirTolerance_SimConVarDef();

  /**
   * Address: 0x00BCE420 (FUN_00BCE420, register_TConVar_ren_Steering)
   *
   * What it does:
   * Registers startup `ren_Steering` convar and installs startup cleanup.
   */
  void register_TConVar_ren_Steering();

  /**
   * Address: 0x00BD4EB0 (FUN_00BD4EB0, register_NoDamage_SimConVarDef)
   *
   * What it does:
   * Registers the `NoDamage` sim convar definition and installs startup cleanup.
   */
  void register_NoDamage_SimConVarDef();

  /**
   * Address: 0x00BD51E0 (FUN_00BD51E0, register_Purge_ConAliasDef)
   *
   * What it does:
   * Registers the `Purge` console alias and installs its startup cleanup thunk.
   */
  void register_Purge_ConAliasDef();

  /**
   * Address: 0x00BD5210 (FUN_00BD5210, register_Purge_SimConFuncDef)
   *
   * What it does:
   * Registers the `Purge` sim command callback and installs startup cleanup.
   */
  void register_Purge_SimConFuncDef();

  /**
   * Address: 0x00BD8380 (FUN_00BD8380, register_DebugAIStatesOff_ConAlias)
   */
  void register_DebugAIStatesOff_ConAlias();

  /**
   * Address: 0x00BD83B0 (FUN_00BD83B0, register_DebugAIStatesOff_SimConFunc)
   */
  void register_DebugAIStatesOff_SimConFunc();

  /**
   * Address: 0x00BD8310 (FUN_00BD8310, register_DebugAIStatesOn_ConAlias)
   */
  void register_DebugAIStatesOn_ConAlias();

  /**
   * Address: 0x00BD8340 (FUN_00BD8340, register_DebugAIStatesOn_SimConFunc)
   */
  void register_DebugAIStatesOn_SimConFunc();

  /**
   * Address: 0x00BDC350 (FUN_00BDC350, register_TrackStats_ConAliasDef)
   *
   * What it does:
   * Registers the `TrackStats` console alias and installs startup cleanup.
   */
  void register_TrackStats_ConAliasDef();

  /**
   * Address: 0x00BDC380 (FUN_00BDC380, register_TrackStats_SimConFuncDef)
   *
   * What it does:
   * Registers the `TrackStats` sim command callback and installs startup
   * cleanup.
   */
  void register_TrackStats_SimConFuncDef();

  /**
   * Address: 0x00BDC3C0 (FUN_00BDC3C0, register_DumpUnits_ConAliasDef)
   *
   * What it does:
   * Registers the `DumpUnits` console alias and installs startup cleanup.
   */
  void register_DumpUnits_ConAliasDef();

  /**
   * Address: 0x00BDC3F0 (FUN_00BDC3F0, register_DumpUnits_SimConFuncDef)
   *
   * What it does:
   * Registers the `DumpUnits` sim command callback and installs startup
   * cleanup.
   */
  void register_DumpUnits_SimConFuncDef();

  /**
   * Address: 0x00BD82A0 (FUN_00BD82A0, register_DebugSetProductionInActive_ConAliasDef)
   */
  void register_DebugSetProductionInActive_ConAliasDef();

  /**
   * Address: 0x00BD82D0 (FUN_00BD82D0, register_DebugSetProductionInActive_SimConFuncDef)
   */
  void register_DebugSetProductionInActive_SimConFuncDef();

  /**
   * Address: 0x00BD8230 (FUN_00BD8230, register_DebugSetProductionActive_ConAliasDef)
   */
  void register_DebugSetProductionActive_ConAliasDef();

  /**
   * Address: 0x00BD8260 (FUN_00BD8260, register_DebugSetProductionActive_SimConFuncDef)
   */
  void register_DebugSetProductionActive_SimConFuncDef();

  /**
   * Address: 0x00BD81C0 (FUN_00BD81C0, register_DebugSetConsumptionInActive_ConAliasDef)
   */
  void register_DebugSetConsumptionInActive_ConAliasDef();

  /**
   * Address: 0x00BD81F0 (FUN_00BD81F0, register_DebugSetConsumptionInActive_SimConFuncDef)
   */
  void register_DebugSetConsumptionInActive_SimConFuncDef();

  /**
   * Address: 0x00BD8150 (FUN_00BD8150, register_DebugSetConsumptionActive_ConAliasDef)
   */
  void register_DebugSetConsumptionActive_ConAliasDef();

  /**
   * Address: 0x00BD8180 (FUN_00BD8180, register_DebugSetConsumptionActive_SimConFuncDef)
   */
  void register_DebugSetConsumptionActive_SimConFuncDef();

  /**
   * Address: 0x00BD6C90 (FUN_00BD6C90, register_KillAll_ConAliasDef)
   */
  void register_KillAll_ConAliasDef();

  /**
   * Address: 0x00BD6CC0 (FUN_00BD6CC0, register_KillAll_SimConFuncDef)
   */
  void register_KillAll_SimConFuncDef();

  /**
   * Address: 0x00BD6D00 (FUN_00BD6D00, register_DestroyAll_ConAliasDef)
   */
  void register_DestroyAll_ConAliasDef();

  /**
   * Address: 0x00BD6D30 (FUN_00BD6D30, register_DestroyAll_SimConFuncDef)
   */
  void register_DestroyAll_SimConFuncDef();

  /** Alias of FUN_00BFE370 (non-canonical helper lane). */
  void cleanup_DebugAIStatesOff_ConAlias();

  /** Address: 0x00BFE3C0 (FUN_00BFE3C0, sub_BFE3C0) */
  void cleanup_DebugAIStatesOff_SimConFunc();

  /** Address: 0x00BFE310 (FUN_00BFE310, sub_BFE310) */
  void cleanup_DebugAIStatesOn_ConAlias();

  /** Address: 0x00BFE360 (FUN_00BFE360, sub_BFE360) */
  void cleanup_DebugAIStatesOn_SimConFunc();

  /**
   * Address: 0x00C01390 (FUN_00C01390, cleanup_TrackStats_ConAlias)
   *
   * What it does:
   * Clears startup-owned `TrackStats` alias payload and unregisters command
   * binding.
   */
  void cleanup_TrackStats_ConAlias();

  /**
   * Address: 0x00C013E0 (FUN_00C013E0, cleanup_TrackStats_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `TrackStats` sim-command callback object.
   */
  void cleanup_TrackStats_SimConFunc();

  /**
   * Address: 0x00C013F0 (FUN_00C013F0, cleanup_DumpUnits_ConAlias)
   *
   * What it does:
   * Clears startup-owned `DumpUnits` alias payload and unregisters command
   * binding.
   */
  void cleanup_DumpUnits_ConAlias();

  /**
   * Address: 0x00C01440 (FUN_00C01440, cleanup_DumpUnits_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `DumpUnits` sim-command callback object.
   */
  void cleanup_DumpUnits_SimConFunc();

  /** Address: 0x00BFE2B0 (FUN_00BFE2B0, sub_BFE2B0) */
  void cleanup_DebugSetProductionInActive_ConAlias();

  /** Address: 0x00BFE300 (FUN_00BFE300, sub_BFE300) */
  void cleanup_DebugSetProductionInActive_SimConFunc();

  /** Address: 0x00BFE250 (FUN_00BFE250, sub_BFE250) */
  void cleanup_DebugSetProductionActive_ConAlias();

  /** Address: 0x00BFE2A0 (FUN_00BFE2A0, sub_BFE2A0) */
  void cleanup_DebugSetProductionActive_SimConFunc();

  /** Address: 0x00BFE1F0 (FUN_00BFE1F0, sub_BFE1F0) */
  void cleanup_DebugSetConsumptionInActive_ConAlias();

  /** Address: 0x00BFE240 (FUN_00BFE240, sub_BFE240) */
  void cleanup_DebugSetConsumptionInActive_SimConFunc();

  /** Address: 0x00BFE190 (FUN_00BFE190, sub_BFE190) */
  void cleanup_DebugSetConsumptionActive_ConAlias();

  /** Address: 0x00BFE1E0 (FUN_00BFE1E0, sub_BFE1E0) */
  void cleanup_DebugSetConsumptionActive_SimConFunc();

  /**
   * Address: 0x00BFC630 (FUN_00BFC630, sub_BFC630)
   *
   * What it does:
   * Clears startup-owned `NoDamage` alias payload and unregisters command binding.
   */
  void cleanup_NoDamage_ConAlias();

  /**
   * Address: 0x00BFC680 (FUN_00BFC680, sub_BFC680)
   *
   * What it does:
   * Destroys startup-owned `NoDamage` sim-convar command object.
   */
  void cleanup_NoDamage_SimConVar();

  /**
   * Address: 0x00BF5F80 (FUN_00BF5F80, sub_BF5F80)
   *
   * What it does:
   * Clears startup-owned `AI_RunOpponentAI` alias payload and unregisters
   * command binding.
   */
  void cleanup_AI_RunOpponentAI_ConAlias();

  /**
   * Address: 0x00BF5FD0 (FUN_00BF5FD0, sub_BF5FD0)
   *
   * What it does:
   * Destroys startup-owned `AI_RunOpponentAI` sim-convar command object.
   */
  void cleanup_AI_RunOpponentAI_SimConVarDef();

  /**
   * Address: 0x00BF5FE0 (FUN_00BF5FE0, sub_BF5FE0)
   *
   * What it does:
   * Clears startup-owned `AI_DebugArmyIndex` alias payload and unregisters
   * command binding.
   */
  void cleanup_AI_DebugArmyIndex_ConAlias();

  /**
   * Address: 0x00BF6030 (FUN_00BF6030, sub_BF6030)
   *
   * What it does:
   * Destroys startup-owned `AI_DebugArmyIndex` sim-convar command object.
   */
  void cleanup_AI_DebugArmyIndex_SimConDef();

  /**
   * Address: 0x00BF6040 (FUN_00BF6040, sub_BF6040)
   *
   * What it does:
   * Clears startup-owned `AI_RenderDebugAttackVectors` alias payload and
   * unregisters command binding.
   */
  void cleanup_AI_RenderDebugAttackVectors_ConAlias();

  /**
   * Address: 0x00BF6090 (FUN_00BF6090, sub_BF6090)
   *
   * What it does:
   * Destroys startup-owned `AI_RenderDebugAttackVectors` sim-convar command
   * object.
   */
  void cleanup_AI_RenderDebugAttackVectors_SimConVarDef();

  /**
   * Address: 0x00BF60A0 (FUN_00BF60A0, sub_BF60A0)
   *
   * What it does:
   * Clears startup-owned `AI_RenderDebugPlayableRect` alias payload and
   * unregisters command binding.
   */
  void cleanup_AI_RenderDebugPlayableRect_ConAlias();

  /**
   * Address: 0x00BF60F0 (FUN_00BF60F0, sub_BF60F0)
   *
   * What it does:
   * Destroys startup-owned `AI_RenderDebugPlayableRect` sim-convar command
   * object.
   */
  void cleanup_AI_RenderDebugPlayableRect_SimConVarDef();

  /**
   * Address: 0x00BF6100 (FUN_00BF6100, sub_BF6100)
   *
   * What it does:
   * Clears startup-owned `AI_DebugCollision` alias payload and unregisters
   * command binding.
   */
  void cleanup_AI_DebugCollision_ConAlias();

  /**
   * Address: 0x00BF6150 (FUN_00BF6150, sub_BF6150)
   *
   * What it does:
   * Destroys startup-owned `AI_DebugCollision` sim-convar command object.
   */
  void cleanup_AI_DebugCollision_SimConVarDef();

  /**
   * Address: 0x00BF6160 (FUN_00BF6160, sub_BF6160)
   *
   * What it does:
   * Clears startup-owned `AI_DebugIgnorePlayableRect` alias payload and
   * unregisters command binding.
   */
  void cleanup_AI_DebugIgnorePlayableRect_ConAlias();

  /**
   * Address: 0x00BF61B0 (FUN_00BF61B0, sub_BF61B0)
   *
   * What it does:
   * Destroys startup-owned `AI_DebugIgnorePlayableRect` sim-convar command
   * object.
   */
  void cleanup_AI_DebugIgnorePlayableRect_SimConVarDef();

  /**
   * Address: 0x00BF9180 (FUN_00BF9180, cleanup_ai_InstaBuild_ConAlias)
   *
   * What it does:
   * Clears startup-owned `ai_InstaBuild` alias payload and unregisters command
   * binding.
   */
  void cleanup_ai_InstaBuild_ConAlias();

  /**
   * Address: 0x00BF91D0 (FUN_00BF91D0, cleanup_ai_InstaBuild_SimConVar)
   *
   * What it does:
   * Destroys startup-owned `ai_InstaBuild` sim-convar command object.
   */
  void cleanup_ai_InstaBuild_SimConVar();

  /**
   * Address: 0x00BF91E0 (FUN_00BF91E0, cleanup_ai_FreeBuild_ConAlias)
   *
   * What it does:
   * Clears startup-owned `ai_FreeBuild` alias payload and unregisters command
   * binding.
   */
  void cleanup_ai_FreeBuild_ConAlias();

  /**
   * Address: 0x00BF9230 (FUN_00BF9230, cleanup_ai_FreeBuild_SimConVar)
   *
   * What it does:
   * Destroys startup-owned `ai_FreeBuild` sim-convar command object.
   */
  void cleanup_ai_FreeBuild_SimConVar();

  /**
   * Address: 0x00BF8040 (FUN_00BF8040, cleanup_ai_SteeringAirTolerance_ConAlias)
   *
   * What it does:
   * Clears startup-owned `ai_SteeringAirTolerance` alias payload and unregisters
   * command binding.
   */
  void cleanup_ai_SteeringAirTolerance_ConAlias();

  /**
   * Address: 0x00BF8090 (FUN_00BF8090, cleanup_ai_SteeringAirTolerance_SimConVar)
   *
   * What it does:
   * Destroys startup-owned `ai_SteeringAirTolerance` sim-convar command object.
   */
  void cleanup_ai_SteeringAirTolerance_SimConVar();

  /**
   * Address: 0x00BF80A0 (FUN_00BF80A0, cleanup_TConVar_ren_Steering)
   *
   * What it does:
   * Tears down startup-owned `ren_Steering` console convar registration.
   */
  void cleanup_TConVar_ren_Steering();

  /**
   * Address: 0x00BFCB00 (FUN_00BFCB00, sub_BFCB00)
   *
   * What it does:
   * Clears startup-owned `Purge` alias payload and unregisters command binding.
   */
  void cleanup_Purge_ConAlias();

  /**
   * Address: 0x00BFCB50 (FUN_00BFCB50, cleanup_Purge_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `Purge` sim-command callback object.
   */
  void cleanup_Purge_SimConFunc();

  /**
   * Address: 0x00BFDD50 (FUN_00BFDD50, cleanup_KillAll_ConAlias)
   */
  void cleanup_KillAll_ConAlias();

  /**
   * Address: 0x00BFDDA0 (FUN_00BFDDA0, cleanup_KillAll_SimConFunc)
   */
  void cleanup_KillAll_SimConFunc();

  /**
   * Address: 0x00BFDDB0 (FUN_00BFDDB0, cleanup_DestroyAll_ConAlias)
   */
  void cleanup_DestroyAll_ConAlias();

  /**
   * Address: 0x00BFDE00 (FUN_00BFDE00, cleanup_DestroyAll_SimConFunc)
   */
  void cleanup_DestroyAll_SimConFunc();
} // namespace moho
