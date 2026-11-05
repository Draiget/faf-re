// Part of Unit.cpp, included there: interface and script bits.

/**
 * Address: 0x006AC2C0 (FUN_006AC2C0, ?CreateInterface@Unit@Moho@@MAEXPAUSSyncData@2@@Z)
 *
 * What it does:
 * Queues one unit-create sync packet and marks this entity interface as
 * created for subsequent SyncInterface lanes.
 */
void Unit::CreateInterface(SSyncData* const syncData)
{
  if (syncData != nullptr) {
    SCreateUnitParams createParams{};
    createParams.mEntityId = id_;
    createParams.mBlueprint = BluePrint;
    createParams.mTickCreated = mTickCreated;
    createParams.mConstDat.mBuildStateTag = mConstDat.mBuildStateTag;
    createParams.mConstDat.mStatsRoot = mConstDat.mStatsRoot;
    createParams.mConstDat.mFake = mConstDat.mFake;
    (void)QueueCreateUnitParams(syncData, createParams);
  }

  mInterfaceCreated = 1u;
}

/**
 * Address: 0x006AC3A0 (FUN_006AC3A0, ?SyncInterface@Unit@Moho@@MAEXPAUSSyncData@2@@Z)
 *
 * IDA signature:
 * void __thiscall Moho::Unit::SyncInterface(Moho::Unit* this, Moho::SSyncData* syncData);
 *
 * What it does:
 * Rebuilds the per-sim command / build-queue CmdId snapshots when their source
 * queues are marked dirty, then queues a `{ id_, mUnitVarDat }` record onto
 * `SSyncData::mUnitUpdates` (+0x158) with the recon-flag word set to 28, and
 * finally chains into the base `Entity::SyncInterface`.
 *   1. `mUnitVarDat.mDidRefresh` is cleared up front.
 *   2. If the command queue is present and dirty, the `mCommands` snapshot is
 *      reset to inline storage and rebuilt from the queue's live commands, the
 *      queue's dirty flag is cleared, and `mDidRefresh` is set.
 *   3. If the AI builder is present and its factory queue is dirty, the
 *      `mBuildQueue` snapshot is likewise rebuilt from the builder's factory
 *      command queue, the builder's dirty flag is cleared, and `mDidRefresh` is
 *      set.
 *   4. A default unit-update record is pushed, `id_` + `mUnitVarDat` are copied
 *      into it, and its recon-flag word (+0x230) is set to 28.
 */
void Unit::SyncInterface(SSyncData* const syncData)
{
  SSTIUnitVariableData& varData = VarDat();
  varData.mDidRefresh = false;

  if (CommandQueue != nullptr && CommandQueue->mNeedsRefresh) {
    varData.mCommands.ResetStorageToInline();
    AppendLiveCommandIdsToSnapshot(varData.mCommands, CommandQueue->mCommandVec);
    CommandQueue->mNeedsRefresh = false;
    varData.mDidRefresh = true;
  }

  if (AiBuilder != nullptr && AiBuilder->BuilderIsFactoryQueueDirty()) {
    varData.mBuildQueue.ResetStorageToInline();
    AppendLiveCommandIdsToSnapshot(varData.mBuildQueue, AiBuilder->BuilderGetFactoryCommandQueue());
    AiBuilder->BuilderSetFactoryQueueDirty(false);
    varData.mDidRefresh = true;
  }

  // sim_ParallelSync finishes the copy on workers after the walk; otherwise the serial queue.
  SUnitVariableUpdateEntry* entry = QueueUnitVariableUpdateDeferred(syncData, id_, varData);
  if (entry == nullptr) {
    entry = QueueUnitVariableUpdate(syncData, id_, varData);
  }
  SetUnitUpdateReconFlags(entry, 28);

  Entity::SyncInterface(syncData);
}

/**
 * Address: 0x006AC530 (FUN_006AC530, ?ShowAIDebugInfo@Unit@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Resolves this unit's `AIDebug_<UniqueName>` stat path and clears it from
 * owning army stats.
 */
void Unit::ShowAIDebugInfo(const bool isEnabled)
{
  (void)isEnabled;

  if (ArmyRef == nullptr) {
    return;
  }

  CArmyStats* const armyStats = ArmyRef->GetArmyStats();
  if (armyStats == nullptr) {
    return;
  }

  const fa::string debugStatPath = fa::string("AIDebug_") + GetUniqueName();
  armyStats->Delete(debugStatPath.c_str());
}

/**
 * Address: 0x0062AF70 (FUN_0062AF70, Moho::Unit::DistanceToOccupiedRect)
 *
 * What it does:
 * Finds the first raised-platform quad covering `samplePoint` in local XZ and
 * bilinearly interpolates one additional Y offset for occupancy snap lanes.
 */
float Unit::DistanceToOccupiedRect(const Wm3::Vector3f* const samplePoint)
{
  if (samplePoint == nullptr || IsDead()) {
    return 0.0f;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint == nullptr) {
    return 0.0f;
  }

  const Wm3::Vector3f& unitPosition = GetPosition();
  const float sampleX = samplePoint->x;
  const float sampleZ = samplePoint->z;

  for (const RUnitBlueprintRaisedPlatform& platform : blueprint->Physics.RaisedPlatforms) {
    const float x0 = platform.Vertex0X + unitPosition.x;
    const float x1 = platform.Vertex1X + unitPosition.x;
    const float x3 = platform.Vertex3X + unitPosition.x;

    const float z0 = platform.Vertex0Z + unitPosition.z;
    const float z2 = platform.Vertex2Z + unitPosition.z;
    const float z3 = platform.Vertex3Z + unitPosition.z;

    // 0x0062B0B4-0x0062B0D3: four `comiss` + `ja` rejections, so an unordered
    // lane counts as inside.
    if (!(sampleX > x3) && !(x0 > sampleX) && !(sampleZ > z3) && !(z0 > sampleZ)) {
      const float zBlend = (sampleZ - z0) / (z2 - z0);
      const float yOnLeftEdge = ((platform.Vertex2Y - platform.Vertex0Y) * zBlend) + platform.Vertex0Y;
      const float yOnRightEdge = ((platform.Vertex3Y - platform.Vertex1Y) * zBlend) + platform.Vertex1Y;
      const float xBlend = (sampleX - x0) / (x1 - x0);
      return ((yOnRightEdge - yOnLeftEdge) * xBlend) + yOnLeftEdge;
    }
  }

  return 0.0f;
}

/**
 * Address: 0x006AC600 (FUN_006AC600, ?DebugShowRaisedPlatforms@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * When `ShowRaisedPlatforms` sim-convar is enabled, draws one debug quad per
 * raised-platform blueprint polygon in world space.
 */
void Unit::DebugShowRaisedPlatforms()
{
  if (!SimulationRef) {
    return;
  }

  CSimConVarBase* const showRaisedPlatformsDef = &moho::gSimConVar_ShowRaisedPlatforms;
  if (!showRaisedPlatformsDef) {
    return;
  }

  CSimConVarInstanceBase* const showRaisedPlatforms = SimulationRef->GetSimVar(showRaisedPlatformsDef);
  const void* const valueStorage = showRaisedPlatforms ? showRaisedPlatforms->GetValueStorage() : nullptr;
  if (!valueStorage || !*reinterpret_cast<const std::uint8_t*>(valueStorage)) {
    return;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (!blueprint) {
    return;
  }

  CDebugCanvas* const debugCanvas = SimulationRef->GetDebugCanvas();
  if (!debugCanvas) {
    return;
  }

  const Wm3::Vector3f unitPos = GetPosition();
  for (const RUnitBlueprintRaisedPlatform& platform : blueprint->Physics.RaisedPlatforms) {
    const Wm3::Vector3f p0{
      unitPos.x + platform.Vertex0X,
      unitPos.y + platform.Vertex0Y,
      unitPos.z + platform.Vertex0Z,
    };
    const Wm3::Vector3f p1{
      unitPos.x + platform.Vertex1X,
      unitPos.y + platform.Vertex1Y,
      unitPos.z + platform.Vertex1Z,
    };
    const Wm3::Vector3f p2{
      unitPos.x + platform.Vertex2X,
      unitPos.y + platform.Vertex2Y,
      unitPos.z + platform.Vertex2Z,
    };
    const Wm3::Vector3f p3{
      unitPos.x + platform.Vertex3X,
      unitPos.y + platform.Vertex3Y,
      unitPos.z + platform.Vertex3Z,
    };

    DrawRaisedPlatformEdge(*debugCanvas, p0, p1);
    DrawRaisedPlatformEdge(*debugCanvas, p1, p3);
    DrawRaisedPlatformEdge(*debugCanvas, p3, p2);
    DrawRaisedPlatformEdge(*debugCanvas, p2, p0);
  }
}

// 0x006A7490
void Unit::ToggleScriptBit(const int bitIndex)
{
  const std::uint32_t shift = static_cast<std::uint32_t>(static_cast<std::uint8_t>(bitIndex)) & 0x1Fu;
  const std::uint32_t mask = 1u << shift;

  const UnitAttributes& attributes = GetAttributes();
  if ((attributes.toggleCapsMask & mask) == 0u) {
    return;
  }

  // 0x006A74DC..0x006A751B: the TRANSPORTATION test is on the attach parent
  // (`mAttachInfo` target at unit+0x194), not on this unit.
  if (IsUnitState(kTransportScriptBitGuardState)) {
    if (Entity* const attachParent = mAttachInfo.GetAttachTargetEntity();
        attachParent != nullptr && attachParent->IsInCategory("TRANSPORTATION")) {
      return;
    }
  }

  if ((mUnitVarDat.mScriptbits & mask) != 0u) {
    mUnitVarDat.mScriptbits &= ~mask;
    CallbackInt("OnScriptBitClear", bitIndex);
  } else {
    mUnitVarDat.mScriptbits |= mask;
    CallbackInt("OnScriptBitSet", bitIndex);
  }

  MarkNeedsSyncGameData();
}

/**
 * Address: 0x006A97C0 (FUN_006A97C0)
 *
 * What it does:
 * Updates fire-state storage and marks the dirty-sync lane for replication.
 */
void Unit::SetFireState(const std::int32_t fireState)
{
  if (mUnitVarDat.mFireState == fireState) {
    return;
  }

  mUnitVarDat.mFireState = fireState;
  MarkNeedsSyncGameData();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_UnitWeaponInfoTypeInfo_d3b904, moho::preregister_UnitWeaponInfoTypeInfo)
GPG_PREREGISTER_INIT(preregister_SSTIUnitVariableDataTypeInfo_d3b904, moho::preregister_SSTIUnitVariableDataTypeInfo)

namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct UnitLuaFuncDefBootstrap
  {
    UnitLuaFuncDefBootstrap()
    {
      (void)::moho::func_UnitGetUnitId_LuaFuncDef();
      (void)::moho::func_UnitSetCreator_LuaFuncDef();
      (void)::moho::func_UnitGetCargo_LuaFuncDef();
      (void)::moho::func_UnitAlterArmor_LuaFuncDef();
      (void)::moho::func_UnitGetArmorMult_LuaFuncDef();
      (void)::moho::func_UnitClearFocusEntity_LuaFuncDef();
      (void)::moho::func_UnitSetFocusEntity_LuaFuncDef();
      (void)::moho::func_UnitGetFocusUnit_LuaFuncDef();
      (void)::moho::func_UnitGetWeapon_LuaFuncDef();
      (void)::moho::func_UnitGetWeaponCount_LuaFuncDef();
      (void)::moho::func_UnitGetTargetEntity_LuaFuncDef();
      (void)::moho::func_UnitGetHealth_LuaFuncDef();
      (void)::moho::func_UnitGetAttacker_LuaFuncDef();
      (void)::moho::func_UnitEnableManipulators_LuaFuncDef();
      (void)::moho::func_UnitKillManipulator_LuaFuncDef();
      (void)::moho::func_UnitKillManipulators_LuaFuncDef();
      (void)::moho::func_UnitScaleGetBuiltEmitter_LuaFuncDef();
      (void)::moho::func_UnitSetStrategicUnderlay_LuaFuncDef();
      (void)::moho::func_GetIsPaused_LuaFuncDef();
      (void)::moho::func_GetIsAutoMode_LuaFuncDef();
      (void)::moho::func_SetFireState_LuaFuncDef();
      (void)::moho::func_ToggleFireState_LuaFuncDef();
      (void)::moho::func_GetFireState_LuaFuncDef();
      (void)::moho::func_GetIsSubmerged_LuaFuncDef();
      (void)::moho::func_GetIsAutoSurfaceMode_LuaFuncDef();
      (void)::moho::func_UnitGetGuards_LuaFuncDef();
      (void)::moho::func_UnitGetTransportFerryBeacon_LuaFuncDef();
      (void)::moho::func_UnitGetGuardedUnit_LuaFuncDef();
      (void)::moho::func_UnitHasValidTeleportDest_LuaFuncDef();
      (void)::moho::func_UnitHasMeleeSpaceAroundTarget_LuaFuncDef();
      (void)::moho::func_UnitForceAltFootprint_LuaFuncDef();
      (void)::moho::func_UnitMeleeWarpAdjacentToTarget_LuaFuncDef();
      (void)::moho::func_UnitAddUnitToStorage_LuaFuncDef();
      (void)::moho::func_UnitGetCurrentMoveLocation_LuaFuncDef();
      (void)::moho::func_UnitGiveNukeSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitRemoveNukeSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitGetNukeSiloAmmoCount_LuaFuncDef();
      (void)::moho::func_UnitGiveTacticalSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitRemoveTacticalSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitGetTacticalSiloAmmoCount_LuaFuncDef();
      (void)::moho::func_UnitSetCustomName_LuaFuncDef();
      (void)::moho::func_UnitGetCommandQueue_LuaFuncDef();
      (void)::moho::func_UnitPrintCommandQueue_LuaFuncDef();
      (void)::moho::func_UnitIsIdleState_LuaFuncDef();
      (void)::moho::func_UnitIsStunned_LuaFuncDef();
      (void)::moho::func_UnitIsBeingBuilt_LuaFuncDef();
      (void)::moho::func_UnitIsPaused_LuaFuncDef();
      (void)::moho::func_UnitSetPaused_LuaFuncDef();
      (void)::moho::func_UnitSetConsumptionActive_LuaFuncDef();
      (void)::moho::func_UnitSetConsumptionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitSetConsumptionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitSetRegenRate_LuaFuncDef();
      (void)::moho::func_UnitRevertRegenRate_LuaFuncDef();
      (void)::moho::func_UnitSetBuildRate_LuaFuncDef();
      (void)::moho::func_UnitGetBuildRate_LuaFuncDef();
      (void)::moho::func_UnitSetProductionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitSetProductionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitGetConsumptionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitGetProductionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitGetProductionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitGetResourceConsumed_LuaFuncDef();
      (void)::moho::func_UnitSetElevation_LuaFuncDef();
      (void)::moho::func_UnitRevertElevation_LuaFuncDef();
      (void)::moho::func_UnitSetSpeedMult_LuaFuncDef();
      (void)::moho::func_UnitSetAccMult_LuaFuncDef();
      (void)::moho::func_UnitSetTurnMult_LuaFuncDef();
      (void)::moho::func_UnitSetBreakOffTriggerMult_LuaFuncDef();
      (void)::moho::func_UnitSetBreakOffDistanceMult_LuaFuncDef();
      (void)::moho::func_UnitSetStat_LuaFuncDef();
      (void)::moho::func_UnitSetWorkProgress_LuaFuncDef();
      (void)::moho::func_UnitGetWorkProgress_LuaFuncDef();
      (void)::moho::func_UnitIsUnitState_LuaFuncDef();
      (void)::moho::func_UnitSetProductionActive_LuaFuncDef();
      (void)::moho::func_UnitSetBusy_LuaFuncDef();
      (void)::moho::func_UnitSetBlockCommandQueue_LuaFuncDef();
      (void)::moho::func_UnitSetImmobile_LuaFuncDef();
      (void)::moho::func_UnitSetUnSelectable_LuaFuncDef();
      (void)::moho::func_UnitSetDoNotTarget_LuaFuncDef();
      (void)::moho::func_UnitStopSiloBuild_LuaFuncDef();
      (void)::moho::func_UnitSetIsValidTarget_LuaFuncDef();
      (void)::moho::func_UnitIsValidTarget_LuaFuncDef();
      (void)::moho::func_UnitGetNumBuildOrders_LuaFuncDef();
      (void)::moho::func_UnitCalculateWorldPositionFromRelative_LuaFuncDef();
      (void)::moho::func_UnitSetStunned_LuaFuncDef();
      (void)::moho::func_UnitSetUnitState_LuaFuncDef();
      (void)::moho::func_GetScriptBit_LuaFuncDef();
      (void)::moho::func_UnitGetScriptBit_LuaFuncDef();
      (void)::moho::func_UnitSetScriptBit_LuaFuncDef();
      (void)::moho::func_UnitToggleScriptBit_LuaFuncDef();
      (void)::moho::func_UnitToggleFireState_LuaFuncDef();
      (void)::moho::func_UnitSetFireState_LuaFuncDef();
      (void)::moho::func_UnitGetFireState_LuaFuncDef();
      (void)::moho::func_UnitSetAutoMode_LuaFuncDef();
      (void)::moho::func_UnitAddBuildRestriction_LuaFuncDef();
      (void)::moho::func_UnitRemoveBuildRestriction_LuaFuncDef();
      (void)::moho::func_UnitRestoreBuildRestrictions_LuaFuncDef();
      (void)::moho::func_UnitAddCommandCap_LuaFuncDef();
      (void)::moho::func_UnitRemoveCommandCap_LuaFuncDef();
      (void)::moho::func_UnitRestoreCommandCaps_LuaFuncDef();
      (void)::moho::func_UnitAddToggleCap_LuaFuncDef();
      (void)::moho::func_UnitRemoveToggleCap_LuaFuncDef();
      (void)::moho::func_UnitRestoreToggleCaps_LuaFuncDef();
      (void)::moho::func_UnitTestCommandCaps_LuaFuncDef();
      (void)::moho::func_UnitTestToggleCaps_LuaFuncDef();
      (void)::moho::func_UnitGetRallyPoint_LuaFuncDef();
      (void)::moho::func_UnitGetFuelUseTime_LuaFuncDef();
      (void)::moho::func_UnitGetFuelRatio_LuaFuncDef();
      (void)::moho::func_UnitGetShieldRatio_LuaFuncDef();
      (void)::moho::func_UnitGetBlip_LuaFuncDef();
      (void)::moho::func_UnitTransportHasSpaceFor_LuaFuncDef();
      (void)::moho::func_UnitTransportHasAvailableStorage_LuaFuncDef();
      (void)::moho::func_UnitTransportDetachAllUnits_LuaFuncDef();
      (void)::moho::func_UnitShowBone_LuaFuncDef();
      (void)::moho::func_UnitHideBone_LuaFuncDef();
      (void)::moho::func_UnitSetShieldRatio_LuaFuncDef();
      (void)::moho::func_UnitSetReclaimable_LuaFuncDef();
      (void)::moho::func_UnitSetCapturable_LuaFuncDef();
      (void)::moho::func_UnitIsCapturable_LuaFuncDef();
      (void)::moho::func_UnitSetOverchargePaused_LuaFuncDef();
      (void)::moho::func_UnitIsOverchargePaused_LuaFuncDef();
      (void)::moho::func_UnitRevertCollisionShape_LuaFuncDef();
      (void)::moho::func_UnitRecoilImpulse_LuaFuncDef();
      (void)::moho::func_UnitGetCurrentLayer_LuaFuncDef();
      (void)::moho::func_UnitCanPathTo_LuaFuncDef();
      (void)::moho::func_UnitCanPathToRect_LuaFuncDef();
      (void)::moho::func_UnitIsMobile_LuaFuncDef();
      (void)::moho::func_UnitIsMoving_LuaFuncDef();
      (void)::moho::func_UnitGetNavigator_LuaFuncDef();
      (void)::moho::func_UnitGetVelocity_LuaFuncDef();
      (void)::moho::func_UnitGetStat_LuaFuncDef();
      (void)::moho::func_UnitCanBuild_LuaFuncDef();
      (void)::moho::func_UnitSetFuelUseTime_LuaFuncDef();
      (void)::moho::func_UnitSetFuelRatio_LuaFuncDef();
      (void)::moho::func_CreateUnit2_LuaFuncDef();
      (void)::moho::func_CreateUnit_LuaFuncDef();
      (void)::moho::func_CreateUnitHPR_LuaFuncDef();
    }
  };

  const UnitLuaFuncDefBootstrap gUnitLuaFuncDefBootstrap{};
} // namespace
namespace moho
{
  /**
   * `gpg::SerConstructHelper<Unit>`, vtable 0x00E2A810.
   *
   * Address: 0x00BD6B20 (FUN_00BD6B20 -- constructs the global and registers its destructor.)
   * Address: 0x00BFDA00 (FUN_00BFDA00 -- the global's destructor.)
   * Address: 0x006AE9A0 (FUN_006AE9A0 -- `Init`.)
   * Address: 0x006AD3A0 (FUN_006AD3A0 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x006B1010 (FUN_006B1010 -- `Delete`.)
   */
  struct UnitConstruct : gpg::SerConstructHelper<Unit>
  {};

  /**
   * `gpg::SerSaveConstructHelper<Unit>`, vtable 0x00E2A800.
   *
   * Address: 0x00BD6AF0 (FUN_00BD6AF0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFD9D0 (FUN_00BFD9D0 -- the global's destructor.)
   * Address: 0x006AE920 (FUN_006AE920 -- `Init`.)
   * Address: 0x006AD210 (FUN_006AD210 -- `SaveConstructArgs`, `MemberSaveConstructArgs` inlined.)
   */
  struct UnitSaveConstruct : gpg::SerSaveConstructHelper<Unit>
  {};

  /**
   * `gpg::SerSaveLoadHelper<Unit>`, vtable 0x00E2A820.
   *
   * Address: 0x00BD6B60 (FUN_00BD6B60 -- constructs the global and registers its destructor.)
   * Address: 0x00BFDA30 (FUN_00BFDA30 -- the global's destructor.)
   * Address: 0x006AEA20 (FUN_006AEA20 -- `Init`.)
   * Address: 0x006AD470 (FUN_006AD470 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x006AD490 (FUN_006AD490 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct UnitSerializer : gpg::SerSaveLoadHelper<Unit>
  {};
}

namespace
{
  // Address: 0x010B5BB4 -- process-global `UnitConstruct` singleton.
  moho::UnitConstruct gUnitConstruct;

  // Address: 0x010B5AE8 -- process-global `UnitSaveConstruct` singleton.
  moho::UnitSaveConstruct gUnitSaveConstruct;

  // Address: 0x010B5B80 -- process-global `UnitSerializer` singleton.
  moho::UnitSerializer gUnitSerializer;
}

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SSTIUnitVariableData>`, vtable 0x00E188E4.
   *
   * Address: 0x00BCA6A0 (FUN_00BCA6A0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF54B0 (FUN_00BF54B0 -- the global's destructor.)
   * Address: 0x0055D100 (FUN_0055D100 -- `Init`.)
   * Address: 0x0055C760 (FUN_0055C760 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0055C770 (FUN_0055C770 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SSTIUnitVariableDataSerializer : gpg::SerSaveLoadHelper<SSTIUnitVariableData>
  {};
}

namespace
{
  // Address: 0x010ACB54 -- process-global `SSTIUnitVariableDataSerializer` singleton.
  moho::SSTIUnitVariableDataSerializer gSSTIUnitVariableDataSerializer;
}

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<UnitWeaponInfo>`, vtable 0x00E1879C.
   *
   * Address: 0x00BCA580 (FUN_00BCA580 -- constructs the global and registers its destructor.)
   * Address: 0x00BF5300 (FUN_00BF5300 -- the global's destructor.)
   * Address: 0x0055CA40 (FUN_0055CA40 -- `Init`.)
   * Address: 0x0055C160 (FUN_0055C160 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0055C170 (FUN_0055C170 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct UnitWeaponInfoSerializer : gpg::SerSaveLoadHelper<UnitWeaponInfo>
  {};
}

namespace
{
  // Address: 0x010ACD0C -- process-global `UnitWeaponInfoSerializer` singleton.
  moho::UnitWeaponInfoSerializer gUnitWeaponInfoSerializer;
}
