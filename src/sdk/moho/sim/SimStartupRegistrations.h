#pragma once

namespace moho
{
  class CScrLuaInitForm;
  class CSimConVarBase;

  // Underlying Lua function-definition publishers referenced by this thunk pack.
  CScrLuaInitForm* func_EntityCreatePropAtBone_LuaFuncDef();
  CScrLuaInitForm* func_SplitProp_LuaFuncDef();
  /**
   * Address: 0x006FCAA0 (FUN_006FCAA0, func_EntityPushOver_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:PushOver(nx, ny, nz, depth)` Lua binder form.
   */
  CScrLuaInitForm* func_EntityPushOver_LuaFuncDef();
  /**
   * Address: 0x006FCF60 (FUN_006FCF60, func_PropAddBoundedProp_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Prop:AddBoundedProp(priority)` Lua binder form.
   */
  CScrLuaInitForm* func_PropAddBoundedProp_LuaFuncDef();
  CScrLuaInitForm* func_CreatePropHPR_LuaFuncDef();
  CScrLuaInitForm* func_CreateProp_LuaFuncDef();
  CScrLuaInitForm* func_CreateResourceDeposit_LuaFuncDef();
  CScrLuaInitForm* func_SpecFootprints_LuaFuncDef();
  CScrLuaInitForm* func_ShouldCreateInitialArmyUnits_LuaFuncDef();
  /**
   * Address: 0x005C29F0 (FUN_005C29F0, func_ReconBlipGetBlueprint_LuaFuncDef)
   */
  CScrLuaInitForm* func_ReconBlipGetBlueprint_LuaFuncDef();
  /**
   * Address: 0x005C2B50 (FUN_005C2B50, func_ReconBlipGetSource_LuaFuncDef)
   */
  CScrLuaInitForm* func_ReconBlipGetSource_LuaFuncDef();
  /**
   * Address: 0x005C2CB0 (FUN_005C2CB0, func_ReconBlipIsSeenEver_LuaFuncDef)
   */
  CScrLuaInitForm* func_ReconBlipIsSeenEver_LuaFuncDef();
  /**
   * Address: 0x005C2E20 (FUN_005C2E20, func_ReconBlipIsSeenNow_LuaFuncDef)
   */
  CScrLuaInitForm* func_ReconBlipIsSeenNow_LuaFuncDef();
  /**
   * Address: 0x005C2F90 (FUN_005C2F90, func_ReconBlipIsMaybeDead_LuaFuncDef)
   */
  CScrLuaInitForm* func_ReconBlipIsMaybeDead_LuaFuncDef();
  /**
   * Address: 0x005C3100 (FUN_005C3100, func_ReconBlipIsOnOmni_LuaFuncDef)
   */
  CScrLuaInitForm* func_ReconBlipIsOnOmni_LuaFuncDef();
  /**
   * Address: 0x005C3270 (FUN_005C3270, func_ReconBlipIsOnSonar_LuaFuncDef)
   */
  CScrLuaInitForm* func_ReconBlipIsOnSonar_LuaFuncDef();
  /**
   * Address: 0x005C33E0 (FUN_005C33E0, func_ReconBlipIsOnRadar_LuaFuncDef)
   */
  CScrLuaInitForm* func_ReconBlipIsOnRadar_LuaFuncDef();
  /**
   * Address: 0x005C3550 (FUN_005C3550, func_ReconBlipIsKnownFake_LuaFuncDef)
   */
  CScrLuaInitForm* func_ReconBlipIsKnownFake_LuaFuncDef();

  /**
   * Address: 0x00BFCFB0 (FUN_00BFCFB0, cleanup_tree_AccelFactor_ConAlias)
   *
   * What it does:
   * Tears down recovered `tree_AccelFactor` alias startup storage.
   */
  void cleanup_tree_AccelFactor_ConAlias();

  /**
   * Address: 0x00BD59E0 (FUN_00BD59E0, register_tree_AccelFactor_ConAliasDef)
   *
   * What it does:
   * Initializes recovered `tree_AccelFactor` console alias and registers
   * process-exit cleanup.
   */
  void register_tree_AccelFactor_ConAliasDef();

  /**
   * Address: 0x00BFD000 (FUN_00BFD000, cleanup_tree_AccelFactor_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `tree_AccelFactor` sim-convar startup storage.
   */
  void cleanup_tree_AccelFactor_SimConVarDef();

  /**
   * Address: 0x00BD5A10 (FUN_00BD5A10, register_tree_AccelFactor_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `tree_AccelFactor` float sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_tree_AccelFactor_SimConVarDef();

  /**
   * Address: 0x00BFD010 (FUN_00BFD010, cleanup_tree_SpringFactor_ConAlias)
   *
   * What it does:
   * Tears down recovered `tree_SpringFactor` alias startup storage.
   */
  void cleanup_tree_SpringFactor_ConAlias();

  /**
   * Address: 0x00BD5A60 (FUN_00BD5A60, register_tree_SpringFactor_ConAliasDef)
   *
   * What it does:
   * Initializes recovered `tree_SpringFactor` console alias and registers
   * process-exit cleanup.
   */
  void register_tree_SpringFactor_ConAliasDef();

  /**
   * Address: 0x00BFD060 (FUN_00BFD060, cleanup_tree_SpringFactor_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `tree_SpringFactor` sim-convar startup storage.
   */
  void cleanup_tree_SpringFactor_SimConVarDef();

  /**
   * Address: 0x00BD5A90 (FUN_00BD5A90, register_tree_SpringFactor_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `tree_SpringFactor` float sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_tree_SpringFactor_SimConVarDef();

  /**
   * Address: 0x00BFD070 (FUN_00BFD070, cleanup_tree_DampFactor_ConAlias)
   *
   * What it does:
   * Tears down recovered `tree_DampFactor` alias startup storage.
   */
  void cleanup_tree_DampFactor_ConAlias();

  /**
   * Address: 0x00BD5AE0 (FUN_00BD5AE0, register_tree_DampFactor_ConAliasDef)
   *
   * What it does:
   * Initializes recovered `tree_DampFactor` console alias and registers
   * process-exit cleanup.
   */
  void register_tree_DampFactor_ConAliasDef();

  /**
   * Address: 0x00BFD0C0 (FUN_00BFD0C0, cleanup_tree_DampFactor_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `tree_DampFactor` sim-convar startup storage.
   */
  void cleanup_tree_DampFactor_SimConVarDef();

  /**
   * Address: 0x00BD5B10 (FUN_00BD5B10, register_tree_DampFactor_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `tree_DampFactor` float sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_tree_DampFactor_SimConVarDef();

  /**
   * Address: 0x00BFD0D0 (FUN_00BFD0D0, cleanup_tree_UprootFactor_ConAlias)
   *
   * What it does:
   * Tears down recovered `tree_UprootFactor` alias startup storage.
   */
  void cleanup_tree_UprootFactor_ConAlias();

  /**
   * Address: 0x00BD5B60 (FUN_00BD5B60, register_tree_UprootFactor_ConAliasDef)
   *
   * What it does:
   * Initializes recovered `tree_UprootFactor` console alias and registers
   * process-exit cleanup.
   */
  void register_tree_UprootFactor_ConAliasDef();

  /**
   * Address: 0x00BFD120 (FUN_00BFD120, cleanup_tree_UprootFactor_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `tree_UprootFactor` sim-convar startup storage.
   */
  void cleanup_tree_UprootFactor_SimConVarDef();

  /**
   * Address: 0x00BD5B90 (FUN_00BD5B90, register_tree_UprootFactor_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `tree_UprootFactor` float sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_tree_UprootFactor_SimConVarDef();

  /**
   * Address owner: tree_* startup convar lanes (0x00BD5A10/0x00BD5A90/0x00BD5B10/0x00BD5B90)
   *
   * What it does:
   * Returns the recovered `tree_AccelFactor` sim-convar definition used by
   * tree motor update logic.
   */
  [[nodiscard]] CSimConVarBase* GetTreeAccelFactorSimConVarDef();

  /**
   * Address owner: tree_* startup convar lanes (0x00BD5A10/0x00BD5A90/0x00BD5B10/0x00BD5B90)
   *
   * What it does:
   * Returns the recovered `tree_SpringFactor` sim-convar definition used by
   * tree motor update logic.
   */
  [[nodiscard]] CSimConVarBase* GetTreeSpringFactorSimConVarDef();

  /**
   * Address owner: tree_* startup convar lanes (0x00BD5A10/0x00BD5A90/0x00BD5B10/0x00BD5B90)
   *
   * What it does:
   * Returns the recovered `tree_DampFactor` sim-convar definition used by
   * tree motor update logic.
   */
  [[nodiscard]] CSimConVarBase* GetTreeDampFactorSimConVarDef();

  /**
   * Address owner: tree_* startup convar lanes (0x00BD5A10/0x00BD5A90/0x00BD5B10/0x00BD5B90)
   *
   * What it does:
   * Returns the recovered `tree_UprootFactor` sim-convar definition used by
   * tree motor update logic.
   */
  [[nodiscard]] CSimConVarBase* GetTreeUprootFactorSimConVarDef();

  /**
   * Address: 0x00BFDE30 (FUN_00BFDE30, cleanup_RandomElevationOffset_ConAlias)
   *
   * What it does:
   * Tears down recovered `RandomElevationOffset` alias startup storage.
   */
  void cleanup_RandomElevationOffset_ConAlias();

  /**
   * Address: 0x00BD6F60 (FUN_00BD6F60, register_RandomElevationOffset_ConAlias)
   *
   * What it does:
   * Initializes recovered `RandomElevationOffset` console alias and registers
   * process-exit cleanup.
   */
  void register_RandomElevationOffset_ConAlias();

  /**
   * Address: 0x00BFDE80 (FUN_00BFDE80, cleanup_RandomElevationOffset_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `RandomElevationOffset` sim-convar startup storage.
   */
  void cleanup_RandomElevationOffset_SimConVarDef();

  /**
   * Address: 0x00BD6F90 (FUN_00BD6F90, register_RandomElevationOffset_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `RandomElevationOffset` sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_RandomElevationOffset_SimConVarDef();

  /**
   * Address: 0x00BFE0F0 (FUN_00BFE0F0, cleanup_AirLookAheadMult_ConAlias)
   *
   * What it does:
   * Tears down recovered `AirLookAheadMult` alias startup storage.
   */
  void cleanup_AirLookAheadMult_ConAlias();

  /**
   * Address: 0x00BD74B0 (FUN_00BD74B0, register_AirLookAheadMult_ConAlias)
   *
   * What it does:
   * Initializes recovered `AirLookAheadMult` console alias and registers
   * process-exit cleanup.
   */
  void register_AirLookAheadMult_ConAlias();

  /**
   * Address: 0x00BFE140 (FUN_00BFE140, cleanup_AirLookAheadMult_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `AirLookAheadMult` sim-convar startup storage.
   */
  void cleanup_AirLookAheadMult_SimConVarDef();

  /**
   * Address: 0x00BD74E0 (FUN_00BD74E0, register_AirLookAheadMult_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `AirLookAheadMult` sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_AirLookAheadMult_SimConVarDef();

  /**
   * Address: 0x00BD4BE0 (FUN_00BD4BE0, register_sim_SimInits_mForms_prependStartupLane21)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane21`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane21();

  /**
   * Address: 0x00BD4C00 (FUN_00BD4C00, register_sim_SimInits_mForms_prependStartupLane22)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane22`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane22();

  /**
   * Address: 0x00BD5300 (FUN_00BD5300, register_sim_SimInits_mForms_prependStartupLane23)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane23`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane23();

  /**
   * Address: 0x00BD5C90 (FUN_00BD5C90, register_sim_SimInits_mForms_prependStartupLane24)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane24`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane24();

  /**
   * Address: 0x00BD65E0 (FUN_00BD65E0, register_sim_SimInits_mForms_prependStartupLane25)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane25`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane25();

  /**
   * Address: 0x00BD6600 (FUN_00BD6600, register_sim_SimInits_mForms_prependStartupLane26)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane26`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane26();

  /**
   * Address: 0x00BD7910 (FUN_00BD7910, sub_BD7910)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane27`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane27();

  /**
   * Address: 0x00BD7930 (FUN_00BD7930, sub_BD7930)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane28`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane28();

  /**
   * Address: 0x00BD9800 (FUN_00BD9800, sub_BD9800)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered `moho_weapon_methods.mFactory` startup lane anchor.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependMohoWeaponMethodsFactoryLane();

  /**
   * Address: 0x00BC8E40 (FUN_00BC8E40, register_SpecFootprints_LuaFUncDef)
   *
   * What it does:
   * Forwards `register_SpecFootprints_LuaFuncDef` to
   * `func_SpecFootprints_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SpecFootprints_LuaFuncDef();

  /**
   * Address: 0x00BC97F0 (FUN_00BC97F0, register_CreateResourceDeposit_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CreateResourceDeposit_LuaFuncDef` to
   * `func_CreateResourceDeposit_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CreateResourceDeposit_LuaFuncDef();

  /**
   * Address: 0x00BD9A30 (FUN_00BD9A30, sub_BD9A30)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane30`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane30();

  /**
   * Address: 0x00BD9A70 (FUN_00BD9A70, register_EntityCreatePropAtBone_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_EntityCreatePropAtBone_LuaFuncDef` to `func_EntityCreatePropAtBone_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCreatePropAtBone_LuaFuncDef();

  /**
   * Address: 0x00BD9A80 (FUN_00BD9A80, register_SplitProp_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SplitProp_LuaFuncDef` to `func_SplitProp_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SplitProp_LuaFuncDef();

  /**
   * Address: 0x00BD9A90 (FUN_00BD9A90, register_EntityPushOver_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_EntityPushOver_LuaFuncDef` to `func_EntityPushOver_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityPushOver_LuaFuncDef();

  /**
   * Address: 0x00BD9AA0 (FUN_00BD9AA0, register_PropAddBoundedProp_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_PropAddBoundedProp_LuaFuncDef` to `func_PropAddBoundedProp_LuaFuncDef`.
   */
  CScrLuaInitForm* register_PropAddBoundedProp_LuaFuncDef();

  /**
   * Address: 0x00BD9A50 (FUN_00BD9A50, j_func_CreatePropHPR_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CreatePropHPR_LuaFuncDef` to `func_CreatePropHPR_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreatePropHPR_LuaFuncDef();

  /**
   * Address: 0x00BD9A60 (FUN_00BD9A60, register_CreateProp_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CreateProp_LuaFuncDef` to `func_CreateProp_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CreateProp_LuaFuncDef();

  /**
   * Address: 0x00BD9CF0 (FUN_00BD9CF0, j_func_ShouldCreateInitialArmyUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_ShouldCreateInitialArmyUnits_LuaFuncDef` to `func_ShouldCreateInitialArmyUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_ShouldCreateInitialArmyUnits_LuaFuncDef();

  /**
   * Address: 0x00BDBDE0 (FUN_00BDBDE0, register_EndGame_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_EndGame_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EndGame_LuaFuncDef();

  /**
   * Address: 0x00BDBDF0 (FUN_00BDBDF0, register_IsGameOver_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_IsGameOver_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IsGameOver_LuaFuncDef();

  /**
   * Address: 0x00BDBE00 (FUN_00BDBE00, register_GetEntityById_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetEntityById_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetEntityById_LuaFuncDef();

  /**
   * Address: 0x00BDBE10 (FUN_00BDBE10, register_GetUnitByIdSim_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetUnitByIdSim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetUnitByIdSim_LuaFuncDef();

  /**
   * Address: 0x00BE4D10 (FUN_00BE4D10, register_ClearBuildTemplates_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ClearBuildTemplates_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ClearBuildTemplates_LuaFuncDef();

  /**
   * Address: 0x00BE4D20 (FUN_00BE4D20, j_func_RenderOverlayMilitary_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_RenderOverlayMilitary_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_RenderOverlayMilitary_LuaFuncDef();

  /**
   * Address: 0x00BE4D30 (FUN_00BE4D30, register_RenderOverlayIntel_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_RenderOverlayIntel_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RenderOverlayIntel_LuaFuncDef();

  /**
   * Address: 0x00BE4D40 (FUN_00BE4D40, register_RenderOverlayEconomy_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_RenderOverlayEconomy_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RenderOverlayEconomy_LuaFuncDef();

  /**
   * Address: 0x00BE4D50 (FUN_00BE4D50, j_func_TeamColorModeUser_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_TeamColorMode_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_TeamColorModeUser_LuaFuncDef();

  /**
   * Address: 0x00BE4D60 (FUN_00BE4D60, register_GetUnitByIdUser_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetUnitByIdUser_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetUnitByIdUser_LuaFuncDef();

  /**
   * Address: 0x00BDBF90 (FUN_00BDBF90, register_EntityCategoryContains_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_EntityCategoryContainsSim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategoryContains_LuaFuncDef();

  /**
   * Address: 0x00BDBF00 (FUN_00BDBF00, register_SimConExecute_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_SimConExecute_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SimConExecute_LuaFuncDef();

  /**
   * Address: 0x00BDBFA0 (FUN_00BDBFA0, register_EntityCategoryFilterDownSim_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_EntityCategoryFilterDownSim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategoryFilterDownSim_LuaFuncDef();

  /**
   * Address: 0x00BDBFB0 (FUN_00BDBFB0, register_EntityCategoryCount_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_EntityCategoryCount_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategoryCount_LuaFuncDef();

  /**
   * Address: 0x00BDBFD0 (FUN_00BDBFD0, register_GenerateRandomOrientation_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GenerateRandomOrientation_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GenerateRandomOrientation_LuaFuncDef();

  /**
   * Address: 0x00BDBFE0 (FUN_00BDBFE0, register_GetGameTimeSecondsSim_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetGameTimeSecondsSim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetGameTimeSecondsSim_LuaFuncDef();

  /**
   * Address: 0x00BDBFF0 (FUN_00BDBFF0, register_GetGameTick_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetGameTick_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetGameTick_LuaFuncDef();

  /**
   * Address: 0x00BDC000 (FUN_00BDC000, register_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef();

  /**
   * Address: 0x00BDC050 (FUN_00BDC050, register_Warp_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_Warp_LuaFuncDef`.
   */
  CScrLuaInitForm* register_Warp_LuaFuncDef();

  /**
   * Address: 0x00BDC070 (FUN_00BDC070, register_GetTerrainHeight_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetTerrainHeight_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetTerrainHeight_LuaFuncDef();

  /**
   * Address: 0x00BDC080 (FUN_00BDC080, register_GetSurfaceHeight_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetSurfaceHeight_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetSurfaceHeight_LuaFuncDef();

  /**
   * Address: 0x00BDC090 (FUN_00BDC090, register_GetTerrainTypeOffset_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetTerrainTypeOffset_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetTerrainTypeOffset_LuaFuncDef();

  /**
   * Address: 0x00BDC0A0 (FUN_00BDC0A0, register_GetTerrainType_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetTerrainType_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetTerrainType_LuaFuncDef();

  /**
   * Address: 0x00BDC0B0 (FUN_00BDC0B0, register_SetTerrainType_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_SetTerrainType_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetTerrainType_LuaFuncDef();

  /**
   * Address: 0x00BDC0C0 (FUN_00BDC0C0, register_SetTerrainTypeRect_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_SetTerrainTypeRect_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetTerrainTypeRect_LuaFuncDef();

  /**
   * Address: 0x00BDC0D0 (FUN_00BDC0D0, register_SetPlayableRect_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_SetPlayableRect_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetPlayableRect_LuaFuncDef();

  /**
   * Address: 0x00BDC0E0 (FUN_00BDC0E0, register_FlushIntelInRect_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_FlushIntelInRect_LuaFuncDef`.
   */
  CScrLuaInitForm* register_FlushIntelInRect_LuaFuncDef();

  /**
   * Address: 0x00BDC0F0 (FUN_00BDC0F0, register_GetUnitBlueprintByName_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetUnitBlueprintByName_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetUnitBlueprintByName_LuaFuncDef();

  /**
   * Address: 0x00BDC290 (FUN_00BDC290, register_SetArmyStatsSyncArmy_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_SetArmyStatsSyncArmy_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyStatsSyncArmy_LuaFuncDef();

  /**
   * Address: 0x00BDC2B0 (FUN_00BDC2B0, register_DrawLine_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_DrawLine_LuaFuncDef`.
   */
  CScrLuaInitForm* register_DrawLine_LuaFuncDef();

  /**
   * Address: 0x00BDC2D0 (FUN_00BDC2D0, register_DrawCircle_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_DrawCircle_LuaFuncDef`.
   */
  CScrLuaInitForm* register_DrawCircle_LuaFuncDef();

  /**
   * Address: 0x00BFD880 (FUN_00BFD880, cleanup_ShowRaisedPlatforms_ConAlias)
   *
   * What it does:
   * Tears down recovered `ShowRaisedPlatforms` alias startup storage.
   */
  void cleanup_ShowRaisedPlatforms_ConAlias();

  /**
   * Address: 0x00BD69F0 (FUN_00BD69F0, register_ShowRaisedPlatforms_ConAlias)
   *
   * What it does:
   * Registers the `ShowRaisedPlatforms` alias used by sim debug rendering.
   */
  void register_ShowRaisedPlatforms_ConAlias();

  /**
   * Address: 0x00BFD8D0 (FUN_00BFD8D0, cleanup_ShowRaisedPlatforms_SimConVar)
   *
   * What it does:
   * Tears down recovered `ShowRaisedPlatforms` sim-convar startup storage.
   */
  void cleanup_ShowRaisedPlatforms_SimConVar();

  /**
   * Address: 0x00BD6A20 (FUN_00BD6A20, register_ShowRaisedPlatforms_SimConVar)
   *
   * What it does:
   * Registers/initializes the `ShowRaisedPlatforms` bool sim-convar.
   */
  void register_ShowRaisedPlatforms_SimConVar();

  /**
   * Address: 0x00BD6A20 startup lane dependency
   *
   * What it does:
   * Returns the recovered `ShowRaisedPlatforms` sim-convar definition used by
   * `Unit::DebugShowRaisedPlatforms`.
   */
  [[nodiscard]] CSimConVarBase* GetShowRaisedPlatformsSimConVarDef();

  /**
   * Address: 0x00BD9B20 (FUN_00BD9B20, register_path_ArmyBudget_ConAliasDef)
   *
   * What it does:
   * Registers the `path_ArmyBudget` console alias.
   */
  void register_path_ArmyBudget_ConAliasDef();

  /**
   * Address: 0x00BD9B50 (FUN_00BD9B50, register_path_ArmyBudget_SimConVarDef)
   *
   * What it does:
   * Registers/initializes the `path_ArmyBudget` sim convar (default 2500).
   */
  void register_path_ArmyBudget_SimConVarDef();

  /**
   * Address: 0x00BCCBF0 (FUN_00BCCBF0, register_path_MaxInstantWorkUnits_ConAliasDef)
   *
   * What it does:
   * Registers the `path_MaxInstantWorkUnits` console alias.
   */
  void register_path_MaxInstantWorkUnits_ConAliasDef();

  /**
   * Address: 0x00BCCC20 (FUN_00BCCC20, register_path_MaxInstantWorkUnits_SimConVarDef)
   *
   * What it does:
   * Registers/initializes the `path_MaxInstantWorkUnits` sim convar (default
   * `500`).
   */
  void register_path_MaxInstantWorkUnits_SimConVarDef();

  /**
   * Address: 0x00BCCC70 (FUN_00BCCC70, register_path_UnreachableTimeoutSearchSteps_ConAliasDef)
   *
   * What it does:
   * Registers the `path_UnreachableTimeoutSearchSteps` console alias.
   */
  void register_path_UnreachableTimeoutSearchSteps_ConAliasDef();

  /**
   * Address: 0x00BCCCA0 (FUN_00BCCCA0, register_path_UnreachableTimeoutSearchSteps_SimConVarDef)
   *
   * What it does:
   * Registers/initializes the `path_UnreachableTimeoutSearchSteps` sim convar
   * (default `1000`).
   */
  void register_path_UnreachableTimeoutSearchSteps_SimConVarDef();

  /**
   * Address: 0x00BD8710 (FUN_00BD8710, register_AI_RenderBombDropZone_ConAliasDef)
   *
   * What it does:
   * Registers the `AI_RenderBombDropZone` alias used by `DoSimCommand`.
   */
  void register_AI_RenderBombDropZone_ConAliasDef();

  /**
   * Address: 0x00BD8740 (FUN_00BD8740, register_AI_RenderBombDropZone_SimConVarDef)
   *
   * What it does:
   * Registers/initializes the `AI_RenderBombDropZone` boolean sim convar.
   */
  void register_AI_RenderBombDropZone_SimConVarDef();

  /**
   * Address: 0x00BD8790 (FUN_00BD8790, register_moho_weapon_methods)
   *
   * What it does:
   * Prepends recovered moho-weapon Lua-init anchor to the active `sim` init chain.
   */
  CScrLuaInitForm* register_moho_weapon_methods();

  /**
   * Address: 0x00BCDC10 (FUN_00BCDC10, register_sim_SimInits_mForms_reconBlipAnchorA)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the chain to the
   * recovered recon-blip anchor-A lane.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_reconBlipAnchorA();

  /**
   * Address: 0x00BCDC30 (FUN_00BCDC30, register_sim_SimInits_mForms_reconBlipAnchorB)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the chain to the
   * recovered recon-blip anchor-B lane.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_reconBlipAnchorB();

  /**
   * Address: 0x00BCDF20 (FUN_00BCDF20, register_CScrLuaMetatableFactory_ReconBlip_Index)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered `CScrLuaMetatableFactory<ReconBlip>` startup index lane.
   */
  int register_CScrLuaMetatableFactory_ReconBlip_Index();

  /**
   * Address: 0x00BCDF40 (FUN_00BCDF40, register_CScrLuaMetatableFactory_Entity_Index)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered `CScrLuaMetatableFactory<Entity>` startup index lane.
   */
  int register_CScrLuaMetatableFactory_Entity_Index();

  /**
   * Address: 0x00BCDE00 (FUN_00BCDE00, register_ReconBlipGetBlueprint_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipGetBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipGetBlueprint_LuaFuncDef();

  /**
   * Address: 0x00BCDE10 (FUN_00BCDE10, register_ReconBlipGetSource_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipGetSource_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipGetSource_LuaFuncDef();

  /**
   * Address: 0x00BCDE20 (FUN_00BCDE20, register_ReconBlipIsSeenEver_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsSeenEver_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsSeenEver_LuaFuncDef();

  /**
   * Address: 0x00BCDE30 (FUN_00BCDE30, register_ReconBlipIsSeenNow_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsSeenNow_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsSeenNow_LuaFuncDef();

  /**
   * Address: 0x00BCDE40 (FUN_00BCDE40, register_ReconBlipIsMaybeDead_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsMaybeDead_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsMaybeDead_LuaFuncDef();

  /**
   * Address: 0x00BCDE50 (FUN_00BCDE50, register_ReconBlipIsOnOmni_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsOnOmni_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsOnOmni_LuaFuncDef();

  /**
   * Address: 0x00BCDE60 (FUN_00BCDE60, register_ReconBlipIsOnSonar_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsOnSonar_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsOnSonar_LuaFuncDef();

  /**
   * Address: 0x00BCDE70 (FUN_00BCDE70, register_ReconBlipIsOnRadar_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsOnRadar_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsOnRadar_LuaFuncDef();

  /**
   * Address: 0x00BCDE80 (FUN_00BCDE80, register_ReconBlipIsKnownFake_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsKnownFake_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsKnownFake_LuaFuncDef();

  /**
   * Address: 0x00BF7AE0 (FUN_00BF7AE0, cleanup_ReconFlush_ConAliasDef)
   *
   * What it does:
   * Tears down startup-owned `ReconFlush` console alias payload.
   */
  void cleanup_ReconFlush_ConAliasDef();

  /**
   * Address: 0x00BF7B30 (FUN_00BF7B30, cleanup_ReconFlush_SimConFuncDef)
   *
   * What it does:
   * Destroys startup-owned `ReconFlush` sim-command callback object.
   */
  void cleanup_ReconFlush_SimConFuncDef();

  /**
   * Address: 0x00BCDE90 (FUN_00BCDE90, register_ReconFlush_ConAliasDef)
   *
   * What it does:
   * Registers startup-owned `ReconFlush` console alias.
   */
  void register_ReconFlush_ConAliasDef();

  /**
   * Address: 0x00BCDEC0 (FUN_00BCDEC0, register_ReconFlush_SimConFuncDef)
   *
   * What it does:
   * Registers startup-owned `ReconFlush` sim-command callback.
   */
  void register_ReconFlush_SimConFuncDef();

  /**
   * Address: 0x00C00EF0 (FUN_00C00EF0, CConAlias_ScenarioMethod cleanup)
   *
   * What it does:
   * Tears down startup-owned `ScenarioMethod` console alias payload.
   */
  void cleanup_CConAlias_ScenarioMethod();

  /**
   * Address: 0x00C00F40 (FUN_00C00F40, cleanup_ScenarioMethod_SimConFuncDef)
   *
   * What it does:
   * Destroys startup-owned `ScenarioMethod` sim-command callback object.
   */
  void cleanup_ScenarioMethod_SimConFuncDef();

  /**
   * Address: 0x00BDBCD0 (FUN_00BDBCD0, register_CConAlias_ScenarioMethod)
   *
   * What it does:
   * Registers startup-owned `ScenarioMethod` command alias.
   */
  void register_CConAlias_ScenarioMethod();

  /**
   * Address: 0x00BDBD00 (FUN_00BDBD00, register_ScenarioMethod_SimConFuncDef)
   *
   * What it does:
   * Registers startup-owned `ScenarioMethod` sim-command callback.
   */
  void register_ScenarioMethod_SimConFuncDef();

} // namespace moho



