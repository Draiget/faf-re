// SPDX: faf engine recovery
//
// UnrecoveredLuaCallbackStubs.cpp
//
// Linker stubs for engine Lua callbacks and binder factories whose
// implementations have not yet been recovered from binary evidence.
// Each stub satisfies the link with a no-op behavior:
//   * cfunc_*(lua_State*)       -> returns 0 (no values pushed)
//   * cfunc_*L(LuaPlus::LuaState*) -> returns 0 (no values pushed)
//   * func_*_LuaFuncDef()       -> returns nullptr (lib not registered)
//
// Game scripts that invoke these will see no return values or missing
// bindings. Each stub should be replaced with the recovered
// implementation from the matching FUN_XXXXXXXX address as recovery
// progresses (see decomp/recovery/disasm/fa_full_2026_03_26/).

struct lua_State;

namespace LuaPlus { class LuaState; }

namespace moho
{
  class CScrLuaInitForm;
}

namespace moho
{
  // ===== Unrecovered cfunc(lua_State*) callbacks =====
  int cfunc_CAiBrainCreateResourceBuildingNearest(lua_State*) { return 0; }
  int cfunc_CAiBrainCreateUnitNearSpot(lua_State*) { return 0; }
  int cfunc_CAiBrainFindPlaceToBuild(lua_State*) { return 0; }
  int cfunc_CBoneEntityManipulatorSetPivot(lua_State*) { return 0; }
  int cfunc_CreateAimController(lua_State*) { return 0; }
  int cfunc_CreateBuilderArmController(lua_State*) { return 0; }
  int cfunc_CreateFootPlantController(lua_State*) { return 0; }
  int cfunc_CreateThrustController(lua_State*) { return 0; }
  int cfunc_EntityAttachBoneToEntityBone(lua_State*) { return 0; }
  int cfunc_EntityPushOver(lua_State*) { return 0; }
  int cfunc_EntitySinkAway(lua_State*) { return 0; }
  int cfunc_GenerateBuildTemplateFromSelection(lua_State*) { return 0; }
  int cfunc_GetSessionClients(lua_State*) { return 0; }
  int cfunc_IssueBuildFactory(lua_State*) { return 0; }
  int cfunc_IssueBuildMobile(lua_State*) { return 0; }
  int cfunc_IssueCapture(lua_State*) { return 0; }
  int cfunc_IssueDestroySelf(lua_State*) { return 0; }
  int cfunc_IssueDive(lua_State*) { return 0; }
  int cfunc_IssueFactoryAssist(lua_State*) { return 0; }
  int cfunc_IssueKillSelf(lua_State*) { return 0; }
  int cfunc_IssueMove(lua_State*) { return 0; }
  int cfunc_IssueNuke(lua_State*) { return 0; }
  int cfunc_IssueOverCharge(lua_State*) { return 0; }
  int cfunc_IssueReclaim(lua_State*) { return 0; }
  int cfunc_IssueRepair(lua_State*) { return 0; }
  int cfunc_IssueSacrifice(lua_State*) { return 0; }
  int cfunc_IssueScript(lua_State*) { return 0; }
  int cfunc_IssueTeleport(lua_State*) { return 0; }
  int cfunc_IssueTeleportToBeacon(lua_State*) { return 0; }
  int cfunc_IssueTransportUnload(lua_State*) { return 0; }
  int cfunc_IssueUpgrade(lua_State*) { return 0; }
  int cfunc_LoadSavedGame(lua_State*) { return 0; }
  int cfunc_PrefetchSession(lua_State*) { return 0; }
  int cfunc_UnitHasMeleeSpaceAroundTarget(lua_State*) { return 0; }
  int cfunc_UnitMeleeWarpAdjacentToTarget(lua_State*) { return 0; }
  int func_FlushEvents(lua_State*) { return 0; }
}

namespace moho
{
  // ===== Unrecovered cfunc_*L(LuaPlus::LuaState*) inner callbacks =====
  int cfunc_CPlatoonAggressiveMoveToLocationL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonAttackTargetL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonCanFormPlatoonL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonDestroyL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonFerryToLocationL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonFindClosestUnitL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonFindClosestUnitToBaseL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonFindFurthestUnitL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonFindHighestValueUnitL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonFindPrioritizedUnitL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonFormPlatoonL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonGetFerryBeaconsL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonGuardTargetL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonMoveToLocationL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonMoveToTargetL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonPatrolL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonUnloadAllAtLocationL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonUnloadUnitsAtLocationL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonUseFerryBeaconL(LuaPlus::LuaState*) { return 0; }
  int cfunc_CPlatoonUseTeleporterL(LuaPlus::LuaState*) { return 0; }
  int cfunc_DecreaseBuildCountInQueueL(LuaPlus::LuaState*) { return 0; }
  int cfunc_GetActiveBuildTemplateL(LuaPlus::LuaState*) { return 0; }
  int cfunc_GetRolloverInfoL(LuaPlus::LuaState*) { return 0; }
  int cfunc_GetUnitCommandDataL(LuaPlus::LuaState*) { return 0; }
  int cfunc_IssueBlueprintCommandL(LuaPlus::LuaState*) { return 0; }
  int cfunc_IssueDockCommandL(LuaPlus::LuaState*) { return 0; }
  int cfunc_IssueTacticalL(LuaPlus::LuaState*) { return 0; }
  int cfunc_OpenURLL(LuaPlus::LuaState*) { return 0; }
  int cfunc_SetActiveBuildTemplateL(LuaPlus::LuaState*) { return 0; }
  int cfunc_UISelectAndZoomToL(LuaPlus::LuaState*) { return 0; }
  int cfunc_UISelectionByCategoryL(LuaPlus::LuaState*) { return 0; }
  int cfunc_UIZoomToL(LuaPlus::LuaState*) { return 0; }
}

namespace moho
{
  // ===== Unrecovered func_*_LuaFuncDef binder factories =====
  CScrLuaInitForm* func_CAiBrainCanBuildStructureAt_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_CAiBrainCheckBlockingTerrain_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_CAiBrainGetThreatsAroundPosition_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_CAiBrainGetUnitsAroundPoint_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_CAiBrainPickBestAttackVector_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_CreatePropHPR_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_CreateStorageManip_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_CreateUnit2_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_CreateUnitHPR_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_CreateUnit_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_LUnitMoveNear_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_LUnitMove_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_SplitProp_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func__c_CreateEntity_LuaFuncDef() { return nullptr; }
}

namespace moho
{
  // ===== Unrecovered func_*_LuaFuncDef registrars (void return) =====
  void func_NotifyUpgrade_LuaFuncDef() {}
}
