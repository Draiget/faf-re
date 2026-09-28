#pragma once

namespace moho
{
  class CSimConVarBase;

  /**
   * Cross-TU accessor for the process-wide `NoDamage` sim convar object -- the
   * `SimConVar_NoDamage` global the binary references directly (e.g. from
   * Entity::AdjustHealth). Returns the registration slot installed by
   * register_NoDamage_SimConVarDef(); non-null once sim startup registration has
   * run. Engine code resolves its per-Sim instance via Sim::GetSimVar(...).
   */
  [[nodiscard]] CSimConVarBase* GetNoDamageSimConVar();


  /**
   * Address: 0x00BD38C0 (FUN_00BD38C0, register_SallyShears_SimConFuncDef)
   *
   * What it does:
   * Registers the `SallyShears` sim command callback and installs startup
   * cleanup.
   */
  void register_SallyShears_SimConFuncDef();


  /**
   * Address: 0x00BD3930 (FUN_00BD3930, register_BlingBling_SimConFunc)
   *
   * What it does:
   * Registers the `BlingBling` sim command callback and installs startup
   * cleanup.
   */
  void register_BlingBling_SimConFunc();


  /**
   * Address: 0x00BD39A0 (FUN_00BD39A0, func_ZeroExtraStorage_SimConFuncDef)
   *
   * What it does:
   * Registers the `ZeroExtraStorage` sim command callback and installs startup
   * cleanup.
   */
  void register_ZeroExtraStorage_SimConFuncDef();


  /**
   * Address: 0x00BD3A10 (FUN_00BD3A10, register_DamageUnit_SimConFunc)
   *
   * What it does:
   * Registers the `DamageUnit` sim command callback and installs startup
   * cleanup. The binary's body is the single store
   * `mov SimConFunc_DamageUnit.mFunc, offset Moho__Sim__DamageUnit` at
   * 0x00BD3A31 - this is the only reference to that function in the image.
   */
  void register_DamageUnit_SimConFunc();

  /**
   * Address: 0x00BDC850 (FUN_00BDC850, register_path_GeneratePreview_SimConFuncDef)
   *
   * What it does:
   * Registers the `path_GeneratePreview` sim command callback (drag-to-move
   * pathfind preview) and installs startup cleanup.
   */
  void register_path_GeneratePreview_SimConFuncDef();


  /**
   * Address: 0x00BD3A80 (FUN_00BD3A80, register_AddImpulse_SimConFuncDef)
   *
   * What it does:
   * Registers the `AddImpulse` sim command callback and installs startup
   * cleanup.
   */
  void register_AddImpulse_SimConFuncDef();


  /**
   * Address: 0x00BCE700 (FUN_00BCE700, register_WeaponTerrainBlockageTest_SimConVarDef)
   *
   * What it does:
   * Registers the `WeaponTerrainBlockageTest` sim convar and installs startup
   * cleanup.
   */
  void register_WeaponTerrainBlockageTest_SimConVarDef();


  /**
   * Address: 0x00BD1F90 (FUN_00BD1F90, register_NeedRefuelThresholdRatio_SimConVarDef)
   *
   * What it does:
   * Registers the `NeedRefuelThresholdRatio` sim convar and installs startup
   * cleanup.
   */
  void register_NeedRefuelThresholdRatio_SimConVarDef();


  /**
   * Address: 0x00BD2010 (FUN_00BD2010, register_NeedRepairThresholdRatio_SimConVarDef)
   *
   * What it does:
   * Registers the `NeedRepairThresholdRatio` sim convar and installs startup
   * cleanup.
   */
  void register_NeedRepairThresholdRatio_SimConVarDef();


  /** Address: 0x00BFB4C0 (FUN_00BFB4C0, sub_BFB4C0) */
  void cleanup_SallyShears_SimConFunc();


  /** Address: 0x00BFB520 (FUN_00BFB520, sub_BFB520) */
  void cleanup_BlingBling_SimConFunc();


  /** Address: 0x00BFB580 (FUN_00BFB580, sub_BFB580) */
  void cleanup_ZeroExtraStorage_SimConFunc();



  /** Address: 0x00BFB640 (FUN_00BFB640, sub_BFB640) */
  void cleanup_AddImpulse_SimConFunc();


  /**
   * Address: 0x00BFA770 (FUN_00BFA770, cleanup_NeedRefuelThresholdRatio_SimConVar)
   *
   * What it does:
   * Destroys the startup-owned `NeedRefuelThresholdRatio` sim-convar storage.
   */
  void cleanup_NeedRefuelThresholdRatio_SimConVar();


  /**
   * Address: 0x00BFA7D0 (FUN_00BFA7D0, cleanup_NeedRepairThresholdRatio_SimConVar)
   *
   * What it does:
   * Destroys the startup-owned `NeedRepairThresholdRatio` sim-convar storage.
   */
  void cleanup_NeedRepairThresholdRatio_SimConVar();


  /**
   * Address: 0x00BD3DB0 (FUN_00BD3DB0, register_dbg_SimConFunc)
   *
   * What it does:
   * Registers the startup-owned `dbg` sim command callback.
   */
  void register_dbg_SimConFunc();


  /**
   * Address: 0x00BFB820 (FUN_00BFB820, cleanup_dbg_SimConFunc)
   *
   * What it does:
   * Destroys the startup-owned `dbg` sim command callback object.
   */
  void cleanup_dbg_SimConFunc();



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
   * What it does:
   * Returns the recovered `NeedRefuelThresholdRatio` float sim-convar
   * definition object (default 0.2). Read by `Unit::FindPlatform` to gate
   * air-unit refuel platform search on fuel ratio.
   */
  [[nodiscard]] CSimConVarBase* GetNeedRefuelThresholdRatioSimConVarDef();

  /**
   * What it does:
   * Returns the recovered `NeedRepairThresholdRatio` float sim-convar
   * definition object (default 0.75). Read by `Unit::FindPlatform` to gate
   * air-unit repair platform search on health ratio.
   */
  [[nodiscard]] CSimConVarBase* GetNeedRepairThresholdRatioSimConVarDef();


  /**
   * Address: 0x00BCB100 (FUN_00BCB100, register_AI_DebugArmyIndex_SimConDef)
   *
   * What it does:
   * Registers `AI_DebugArmyIndex` sim convar and installs startup cleanup.
   */
  void register_AI_DebugArmyIndex_SimConDef();


  /**
   * Address: 0x00BCB180 (FUN_00BCB180, register_AI_RenderDebugAttackVectors_SimConVarDef)
   *
   * What it does:
   * Registers `AI_RenderDebugAttackVectors` sim convar and installs startup
   * cleanup.
   */
  void register_AI_RenderDebugAttackVectors_SimConVarDef();


  /**
   * Address: 0x00BCB200 (FUN_00BCB200, register_AI_RenderDebugPlayableRect_SimConVarDef)
   *
   * What it does:
   * Registers `AI_RenderDebugPlayableRect` sim convar and installs startup
   * cleanup.
   */
  void register_AI_RenderDebugPlayableRect_SimConVarDef();


  /**
   * Address: 0x00BCB280 (FUN_00BCB280, register_AI_DebugCollision_SimConVarDef)
   *
   * What it does:
   * Registers `AI_DebugCollision` sim convar and installs startup cleanup.
   */
  void register_AI_DebugCollision_SimConVarDef();


  /**
   * Address: 0x00BCB300 (FUN_00BCB300, register_AI_DebugIgnorePlayableRect_SimConVarDef)
   *
   * What it does:
   * Registers `AI_DebugIgnorePlayableRect` sim convar and installs startup
   * cleanup.
   */
  void register_AI_DebugIgnorePlayableRect_SimConVarDef();


  /**
   * Address: 0x00BCF740 (FUN_00BCF740, register_ai_InstaBuild_SimConVarDef)
   *
   * What it does:
   * Registers the `ai_InstaBuild` sim convar definition and installs startup
   * cleanup.
   */
  void register_ai_InstaBuild_SimConVarDef();


  /**
   * Address: 0x00BCF7C0 (FUN_00BCF7C0, register_ai_FreeBuild_SimConVarDef)
   *
   * What it does:
   * Registers the `ai_FreeBuild` sim convar definition and installs startup
   * cleanup.
   */
  void register_ai_FreeBuild_SimConVarDef();


  /**
   * Address: 0x00BCE3D0 (FUN_00BCE3D0, register_ai_SteeringAirTolerance_SimConVarDef)
   *
   * What it does:
   * Registers `ai_SteeringAirTolerance` sim convar and installs startup
   * cleanup.
   */
  void register_ai_SteeringAirTolerance_SimConVarDef();


  /**
   * Address: 0x00BD4EB0 (FUN_00BD4EB0, register_NoDamage_SimConVarDef)
   *
   * What it does:
   * Registers the `NoDamage` sim convar definition and installs startup cleanup.
   */
  void register_NoDamage_SimConVarDef();


  /**
   * Address: 0x00BD5210 (FUN_00BD5210, register_Purge_SimConFuncDef)
   *
   * What it does:
   * Registers the `Purge` sim command callback and installs startup cleanup.
   */
  void register_Purge_SimConFuncDef();


  /**
   * Address: 0x00BD83B0 (FUN_00BD83B0, register_DebugAIStatesOff_SimConFunc)
   */
  void register_DebugAIStatesOff_SimConFunc();


  /**
   * Address: 0x00BD8340 (FUN_00BD8340, register_DebugAIStatesOn_SimConFunc)
   */
  void register_DebugAIStatesOn_SimConFunc();


  /**
   * Address: 0x00BDC380 (FUN_00BDC380, register_TrackStats_SimConFuncDef)
   *
   * What it does:
   * Registers the `TrackStats` sim command callback and installs startup
   * cleanup.
   */
  void register_TrackStats_SimConFuncDef();


  /**
   * Address: 0x00BDC3F0 (FUN_00BDC3F0, register_DumpUnits_SimConFuncDef)
   *
   * What it does:
   * Registers the `DumpUnits` sim command callback and installs startup
   * cleanup.
   */
  void register_DumpUnits_SimConFuncDef();


  /**
   * Address: 0x00BDC170 (FUN_00BDC170, register_DebugSetPlayableRect_SimConFuncDef)
   *
   * What it does:
   * Registers the `DebugSetPlayableRect` sim command callback and installs
   * startup cleanup. The store at 0x00BDC191
   * (`mov SimConFunc_DebugSetPlayableRect.mFunc, offset Moho__Sim__DebugSetPlayableRect`)
   * is the only reference to `Moho::Sim::DebugSetPlayableRect` anywhere in the
   * image.
   */
  void register_DebugSetPlayableRect_SimConFuncDef();


  /**
   * Address: 0x00BDC1E0 (FUN_00BDC1E0, register_DebugDumpArmyStats_SimConFunc)
   *
   * What it does:
   * Registers the `DebugDumpArmyStats` sim command callback and installs
   * startup cleanup.
   */
  void register_DebugDumpArmyStats_SimConFuncDef();


  /**
   * Address: 0x00BD82D0 (FUN_00BD82D0, register_DebugSetProductionInActive_SimConFuncDef)
   */
  void register_DebugSetProductionInActive_SimConFuncDef();


  /**
   * Address: 0x00BD8260 (FUN_00BD8260, register_DebugSetProductionActive_SimConFuncDef)
   */
  void register_DebugSetProductionActive_SimConFuncDef();


  /**
   * Address: 0x00BD81F0 (FUN_00BD81F0, register_DebugSetConsumptionInActive_SimConFuncDef)
   */
  void register_DebugSetConsumptionInActive_SimConFuncDef();


  /**
   * Address: 0x00BD8180 (FUN_00BD8180, register_DebugSetConsumptionActive_SimConFuncDef)
   */
  void register_DebugSetConsumptionActive_SimConFuncDef();


  /**
   * Address: 0x00BD6CC0 (FUN_00BD6CC0, register_KillAll_SimConFuncDef)
   */
  void register_KillAll_SimConFuncDef();


  /**
   * Address: 0x00BD6D30 (FUN_00BD6D30, register_DestroyAll_SimConFuncDef)
   */
  void register_DestroyAll_SimConFuncDef();


  /** Address: 0x00BFE3C0 (FUN_00BFE3C0, sub_BFE3C0) */
  void cleanup_DebugAIStatesOff_SimConFunc();


  /** Address: 0x00BFE360 (FUN_00BFE360, sub_BFE360) */
  void cleanup_DebugAIStatesOn_SimConFunc();


  /**
   * Address: 0x00C013E0 (FUN_00C013E0, cleanup_TrackStats_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `TrackStats` sim-command callback object.
   */
  void cleanup_TrackStats_SimConFunc();


  /**
   * Address: 0x00C01440 (FUN_00C01440, cleanup_DumpUnits_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `DumpUnits` sim-command callback object.
   */
  void cleanup_DumpUnits_SimConFunc();


  /** Address: 0x00BFE300 (FUN_00BFE300, sub_BFE300) */
  void cleanup_DebugSetProductionInActive_SimConFunc();


  /** Address: 0x00BFE2A0 (FUN_00BFE2A0, sub_BFE2A0) */
  void cleanup_DebugSetProductionActive_SimConFunc();


  /** Address: 0x00BFE240 (FUN_00BFE240, sub_BFE240) */
  void cleanup_DebugSetConsumptionInActive_SimConFunc();


  /** Address: 0x00BFE1E0 (FUN_00BFE1E0, sub_BFE1E0) */
  void cleanup_DebugSetConsumptionActive_SimConFunc();


  /**
   * Address: 0x00BFC680 (FUN_00BFC680, sub_BFC680)
   *
   * What it does:
   * Destroys startup-owned `NoDamage` sim-convar command object.
   */
  void cleanup_NoDamage_SimConVar();


  /**
   * Address: 0x00BF5FD0 (FUN_00BF5FD0, sub_BF5FD0)
   *
   * What it does:
   * Destroys startup-owned `AI_RunOpponentAI` sim-convar command object.
   */
  void cleanup_AI_RunOpponentAI_SimConVarDef();


  /**
   * Address: 0x00BF6030 (FUN_00BF6030, sub_BF6030)
   *
   * What it does:
   * Destroys startup-owned `AI_DebugArmyIndex` sim-convar command object.
   */
  void cleanup_AI_DebugArmyIndex_SimConDef();


  /**
   * Address: 0x00BF6090 (FUN_00BF6090, sub_BF6090)
   *
   * What it does:
   * Destroys startup-owned `AI_RenderDebugAttackVectors` sim-convar command
   * object.
   */
  void cleanup_AI_RenderDebugAttackVectors_SimConVarDef();


  /**
   * Address: 0x00BF60F0 (FUN_00BF60F0, sub_BF60F0)
   *
   * What it does:
   * Destroys startup-owned `AI_RenderDebugPlayableRect` sim-convar command
   * object.
   */
  void cleanup_AI_RenderDebugPlayableRect_SimConVarDef();


  /**
   * Address: 0x00BF6150 (FUN_00BF6150, sub_BF6150)
   *
   * What it does:
   * Destroys startup-owned `AI_DebugCollision` sim-convar command object.
   */
  void cleanup_AI_DebugCollision_SimConVarDef();


  /**
   * Address: 0x00BF61B0 (FUN_00BF61B0, sub_BF61B0)
   *
   * What it does:
   * Destroys startup-owned `AI_DebugIgnorePlayableRect` sim-convar command
   * object.
   */
  void cleanup_AI_DebugIgnorePlayableRect_SimConVarDef();


  /**
   * Address: 0x00BF91D0 (FUN_00BF91D0, cleanup_ai_InstaBuild_SimConVar)
   *
   * What it does:
   * Destroys startup-owned `ai_InstaBuild` sim-convar command object.
   */
  void cleanup_ai_InstaBuild_SimConVar();


  /**
   * Address: 0x00BF9230 (FUN_00BF9230, cleanup_ai_FreeBuild_SimConVar)
   *
   * What it does:
   * Destroys startup-owned `ai_FreeBuild` sim-convar command object.
   */
  void cleanup_ai_FreeBuild_SimConVar();


  /**
   * Address: 0x00BF8090 (FUN_00BF8090, cleanup_ai_SteeringAirTolerance_SimConVar)
   *
   * What it does:
   * Destroys startup-owned `ai_SteeringAirTolerance` sim-convar command object.
   */
  void cleanup_ai_SteeringAirTolerance_SimConVar();



  /**
   * Address: 0x00BFCB50 (FUN_00BFCB50, cleanup_Purge_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `Purge` sim-command callback object.
   */
  void cleanup_Purge_SimConFunc();


  /**
   * Address: 0x00BFDDA0 (FUN_00BFDDA0, cleanup_KillAll_SimConFunc)
   */
  void cleanup_KillAll_SimConFunc();


  /**
   * Address: 0x00BFDE00 (FUN_00BFDE00, cleanup_DestroyAll_SimConFunc)
   */
  void cleanup_DestroyAll_SimConFunc();
} // namespace moho
