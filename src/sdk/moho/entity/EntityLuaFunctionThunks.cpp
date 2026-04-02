#include "moho/lua/CScrLuaInitForm.h"

namespace
{
  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardEntityLuaThunk() noexcept
  {
    return Target();
  }
} // namespace

namespace moho
{
  CScrLuaInitForm* func_EntityCreateProjectile_LuaFuncDef();
  CScrLuaInitForm* func_EntityCreateProjectileAtBone_LuaFuncDef();
  CScrLuaInitForm* func_EntityShakeCamera_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetAIBrain_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetBlueprint_LuaFuncDef();
  CScrLuaInitForm* func_GetBlueprintSim_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetArmy_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetBoneDirection_LuaFuncDef();
  CScrLuaInitForm* func_EntityIsValidBone_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetBoneCount_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetBoneName_LuaFuncDef();
  CScrLuaInitForm* func_EntityRequestRefreshUI_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetEntityId_LuaFuncDef();
  CScrLuaInitForm* func_EntityAttachTo_LuaFuncDef();
  CScrLuaInitForm* func_EntityAttachBoneTo_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetParentOffset_LuaFuncDef();
  CScrLuaInitForm* func_EntityDetachFrom_LuaFuncDef();
  CScrLuaInitForm* func_EntityDetachAll_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetParent_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetCollisionExtents_LuaFuncDef();
  CScrLuaInitForm* func_EntityPlaySound_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetAmbientSound_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetFractionComplete_LuaFuncDef();
  CScrLuaInitForm* func_EntityAdjustHealth_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetHealth_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetMaxHealth_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetHealth_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetMaxHealth_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetVizToFocusPlayer_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetVizToEnemies_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetVizToAllies_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetVizToNeutrals_LuaFuncDef();
  CScrLuaInitForm* func_EntityIsIntelEnabled_LuaFuncDef();
  CScrLuaInitForm* func_EntityEnableIntel_LuaFuncDef();
  CScrLuaInitForm* func_EntityDisableIntel_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetIntelRadius_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetIntelRadius_LuaFuncDef();
  CScrLuaInitForm* func_EntityInitIntel_LuaFuncDef();
  CScrLuaInitForm* func_EntityAddShooter_LuaFuncDef();
  CScrLuaInitForm* func_EntityRemoveShooter_LuaFuncDef();
  CScrLuaInitForm* func_EntityReachedMaxShooters_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetCollisionShape_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetOrientation_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetOrientation_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetHeading_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetPosition_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetPosition_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetPositionXYZ_LuaFuncDef();
  CScrLuaInitForm* func_EntityAddLocalImpulse_LuaFuncDef();
  CScrLuaInitForm* func_EntityAddWorldImpulse_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetMesh_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetDrawScale_LuaFuncDef();
  CScrLuaInitForm* func_EntityGetScale_LuaFuncDef();
  CScrLuaInitForm* func_EntitySetScale_LuaFuncDef();
  CScrLuaInitForm* func_EntityAddManualScroller_LuaFuncDef();
  CScrLuaInitForm* func_EntityAddThreadScroller_LuaFuncDef();
  CScrLuaInitForm* func_EntityAddPingPongScroller_LuaFuncDef();
  CScrLuaInitForm* func_EntityRemoveScroller_LuaFuncDef();
  CScrLuaInitForm* func_EntityDestroy_LuaFuncDef();
  CScrLuaInitForm* func_EntityBeenDestroyed_LuaFuncDef();
  CScrLuaInitForm* func_EntityKill_LuaFuncDef();
  CScrLuaInitForm* func__c_CreateEntity_LuaFuncDef();
  CScrLuaInitForm* func_EntityFallDown_LuaFuncDef();
  CScrLuaInitForm* func_MotorFallDownWhack_LuaFuncDef();
  CScrLuaInitForm* func_EntitySinkAway_LuaFuncDef();

  /**
   * Address: 0x00BD5320 (FUN_00BD5320, register_EntityCreateProjectile_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityCreateProjectile_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityCreateProjectile_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5330 (FUN_00BD5330, register_EntityCreateProjectileAtBone_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityCreateProjectileAtBone_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityCreateProjectileAtBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5340 (FUN_00BD5340, register_EntityShakeCamera_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityShakeCamera_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityShakeCamera_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5350 (FUN_00BD5350, register_EntityGetAIBrain_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetAIBrain_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetAIBrain_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5360 (FUN_00BD5360, register_EntityGetBlueprint_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetBlueprint_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetBlueprint_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5370 (FUN_00BD5370, register_GetBlueprintSim_LuaFuncDef)
   */
  CScrLuaInitForm* register_GetBlueprintSim_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_GetBlueprintSim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5380 (FUN_00BD5380, register_EntityGetArmy_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetArmy_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetArmy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5390 (FUN_00BD5390, register_EntityGetBoneDirection_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetBoneDirection_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetBoneDirection_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD53A0 (FUN_00BD53A0, register_EntityIsValidBone_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityIsValidBone_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityIsValidBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD53B0 (FUN_00BD53B0, register_EntityGetBoneCount_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetBoneCount_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetBoneCount_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD53C0 (FUN_00BD53C0, register_EntityGetBoneName_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetBoneName_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetBoneName_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD53D0 (FUN_00BD53D0, register_EntityRequestRefreshUI_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityRequestRefreshUI_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityRequestRefreshUI_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD53E0 (FUN_00BD53E0, register_EntityGetEntityId_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetEntityId_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetEntityId_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD53F0 (FUN_00BD53F0, register_EntityAttachTo_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityAttachTo_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityAttachTo_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5400 (FUN_00BD5400, register_EntityAttachBoneTo_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityAttachBoneTo_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityAttachBoneTo_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5410 (FUN_00BD5410, register_EntitySetParentOffset_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetParentOffset_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetParentOffset_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5420 (FUN_00BD5420, register_EntityDetachFrom_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityDetachFrom_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityDetachFrom_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5430 (FUN_00BD5430, register_EntityDetachAll_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityDetachAll_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityDetachAll_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5440 (FUN_00BD5440, register_EntityGetParent_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetParent_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetParent_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5450 (FUN_00BD5450, register_EntityGetCollisionExtents_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetCollisionExtents_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetCollisionExtents_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5460 (FUN_00BD5460, register_EntityPlaySound_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityPlaySound_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityPlaySound_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5470 (FUN_00BD5470, register_EntitySetAmbientSound_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetAmbientSound_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetAmbientSound_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5480 (FUN_00BD5480, register_EntityGetFractionComplete_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetFractionComplete_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetFractionComplete_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5490 (FUN_00BD5490, register_EntityAdjustHealth_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityAdjustHealth_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityAdjustHealth_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD54A0 (FUN_00BD54A0, register_EntityGetHealth_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetHealth_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetHealth_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD54B0 (FUN_00BD54B0, register_EntityGetMaxHealth_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetMaxHealth_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetMaxHealth_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD54C0 (FUN_00BD54C0, register_EntitySetHealth_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetHealth_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetHealth_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD54D0 (FUN_00BD54D0, register_EntitySetMaxHealth_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetMaxHealth_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetMaxHealth_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD54E0 (FUN_00BD54E0, register_EntitySetVizToFocusPlayer_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetVizToFocusPlayer_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetVizToFocusPlayer_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD54F0 (FUN_00BD54F0, register_EntitySetVizToEnemies_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetVizToEnemies_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetVizToEnemies_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5500 (FUN_00BD5500, register_EntitySetVizToAllies_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetVizToAllies_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetVizToAllies_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5510 (FUN_00BD5510, register_EntitySetVizToNeutrals_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetVizToNeutrals_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetVizToNeutrals_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5520 (FUN_00BD5520, register_EntityIsIntelEnabled_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityIsIntelEnabled_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityIsIntelEnabled_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5530 (FUN_00BD5530, register_EntityEnableIntel_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityEnableIntel_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityEnableIntel_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5540 (FUN_00BD5540, register_EntityDisableIntel_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityDisableIntel_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityDisableIntel_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5550 (FUN_00BD5550, register_EntitySetIntelRadius_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetIntelRadius_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetIntelRadius_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5560 (FUN_00BD5560, register_EntityGetIntelRadius_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetIntelRadius_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetIntelRadius_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5570 (FUN_00BD5570, register_EntityInitIntel_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityInitIntel_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityInitIntel_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5580 (FUN_00BD5580, register_EntityAddShooter_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityAddShooter_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityAddShooter_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5590 (FUN_00BD5590, register_EntityRemoveShooter_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityRemoveShooter_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityRemoveShooter_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD55A0 (FUN_00BD55A0, register_EntityReachedMaxShooters_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityReachedMaxShooters_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityReachedMaxShooters_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD55B0 (FUN_00BD55B0, register_EntitySetCollisionShape_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetCollisionShape_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetCollisionShape_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD55C0 (FUN_00BD55C0, register_EntityGetOrientation_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetOrientation_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetOrientation_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD55D0 (FUN_00BD55D0, register_EntitySetOrientation_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetOrientation_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetOrientation_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD55E0 (FUN_00BD55E0, register_EntityGetHeading_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetHeading_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetHeading_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD55F0 (FUN_00BD55F0, register_EntitySetPosition_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetPosition_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetPosition_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5600 (FUN_00BD5600, register_EntityGetPosition_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetPosition_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetPosition_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5610 (FUN_00BD5610, register_EntityGetPositionXYZ_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetPositionXYZ_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetPositionXYZ_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5620 (FUN_00BD5620, register_EntityAddLocalImpulse_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityAddLocalImpulse_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityAddLocalImpulse_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5630 (FUN_00BD5630, register_EntityAddWorldImpulse_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityAddWorldImpulse_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityAddWorldImpulse_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5640 (FUN_00BD5640, register_EntitySetMesh_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetMesh_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetMesh_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5650 (FUN_00BD5650, register_EntitySetDrawScale_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetDrawScale_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetDrawScale_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5660 (FUN_00BD5660, register_EntityGetScale_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityGetScale_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityGetScale_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5670 (FUN_00BD5670, register_EntitySetScale_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntitySetScale_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySetScale_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5680 (FUN_00BD5680, register_EntityAddManualScroller_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityAddManualScroller_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityAddManualScroller_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5690 (FUN_00BD5690, register_EntityAddThreadScroller_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityAddThreadScroller_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityAddThreadScroller_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD56A0 (FUN_00BD56A0, register_EntityAddPingPongScroller_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityAddPingPongScroller_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityAddPingPongScroller_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD56B0 (FUN_00BD56B0, register_EntityRemoveScroller_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityRemoveScroller_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityRemoveScroller_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD56C0 (FUN_00BD56C0, register_EntityDestroy_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityDestroy_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityDestroy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD56D0 (FUN_00BD56D0, register_EntityBeenDestroyed_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityBeenDestroyed_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityBeenDestroyed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD56E0 (FUN_00BD56E0, register_EntityKill_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityKill_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityKill_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD56F0 (FUN_00BD56F0, register__c_CreateEntity_LuaFuncDef)
   */
  CScrLuaInitForm* register__c_CreateEntity_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func__c_CreateEntity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5C80 (FUN_00BD5C80, register_EntityFallDown_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityFallDown_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntityFallDown_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5CB0 (FUN_00BD5CB0, j_func_MotorFallDownWhack_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_MotorFallDownWhack_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_MotorFallDownWhack_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD5DF0 (FUN_00BD5DF0, j_func_EntitySinkAway_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_EntitySinkAway_LuaFuncDef()
  {
    return ForwardEntityLuaThunk<&func_EntitySinkAway_LuaFuncDef>();
  }
} // namespace moho

namespace
{
  struct EntityLuaFunctionThunksBootstrap
  {
    EntityLuaFunctionThunksBootstrap()
    {
      (void)moho::register_EntityCreateProjectile_LuaFuncDef();
      (void)moho::register_EntityCreateProjectileAtBone_LuaFuncDef();
      (void)moho::register_EntityShakeCamera_LuaFuncDef();
      (void)moho::register_EntityGetAIBrain_LuaFuncDef();
      (void)moho::register_EntityGetBlueprint_LuaFuncDef();
      (void)moho::register_GetBlueprintSim_LuaFuncDef();
      (void)moho::register_EntityGetArmy_LuaFuncDef();
      (void)moho::register_EntityGetBoneDirection_LuaFuncDef();
      (void)moho::register_EntityIsValidBone_LuaFuncDef();
      (void)moho::register_EntityGetBoneCount_LuaFuncDef();
      (void)moho::register_EntityGetBoneName_LuaFuncDef();
      (void)moho::register_EntityRequestRefreshUI_LuaFuncDef();
      (void)moho::register_EntityGetEntityId_LuaFuncDef();
      (void)moho::register_EntityAttachTo_LuaFuncDef();
      (void)moho::register_EntityAttachBoneTo_LuaFuncDef();
      (void)moho::register_EntitySetParentOffset_LuaFuncDef();
      (void)moho::register_EntityDetachFrom_LuaFuncDef();
      (void)moho::register_EntityDetachAll_LuaFuncDef();
      (void)moho::register_EntityGetParent_LuaFuncDef();
      (void)moho::register_EntityGetCollisionExtents_LuaFuncDef();
      (void)moho::register_EntityPlaySound_LuaFuncDef();
      (void)moho::register_EntitySetAmbientSound_LuaFuncDef();
      (void)moho::register_EntityGetFractionComplete_LuaFuncDef();
      (void)moho::register_EntityAdjustHealth_LuaFuncDef();
      (void)moho::register_EntityGetHealth_LuaFuncDef();
      (void)moho::register_EntityGetMaxHealth_LuaFuncDef();
      (void)moho::register_EntitySetHealth_LuaFuncDef();
      (void)moho::register_EntitySetMaxHealth_LuaFuncDef();
      (void)moho::register_EntitySetVizToFocusPlayer_LuaFuncDef();
      (void)moho::register_EntitySetVizToEnemies_LuaFuncDef();
      (void)moho::register_EntitySetVizToAllies_LuaFuncDef();
      (void)moho::register_EntitySetVizToNeutrals_LuaFuncDef();
      (void)moho::register_EntityIsIntelEnabled_LuaFuncDef();
      (void)moho::register_EntityEnableIntel_LuaFuncDef();
      (void)moho::register_EntityDisableIntel_LuaFuncDef();
      (void)moho::register_EntitySetIntelRadius_LuaFuncDef();
      (void)moho::register_EntityGetIntelRadius_LuaFuncDef();
      (void)moho::register_EntityInitIntel_LuaFuncDef();
      (void)moho::register_EntityAddShooter_LuaFuncDef();
      (void)moho::register_EntityRemoveShooter_LuaFuncDef();
      (void)moho::register_EntityReachedMaxShooters_LuaFuncDef();
      (void)moho::register_EntitySetCollisionShape_LuaFuncDef();
      (void)moho::register_EntityGetOrientation_LuaFuncDef();
      (void)moho::register_EntitySetOrientation_LuaFuncDef();
      (void)moho::register_EntityGetHeading_LuaFuncDef();
      (void)moho::register_EntitySetPosition_LuaFuncDef();
      (void)moho::register_EntityGetPosition_LuaFuncDef();
      (void)moho::register_EntityGetPositionXYZ_LuaFuncDef();
      (void)moho::register_EntityAddLocalImpulse_LuaFuncDef();
      (void)moho::register_EntityAddWorldImpulse_LuaFuncDef();
      (void)moho::register_EntitySetMesh_LuaFuncDef();
      (void)moho::register_EntitySetDrawScale_LuaFuncDef();
      (void)moho::register_EntityGetScale_LuaFuncDef();
      (void)moho::register_EntitySetScale_LuaFuncDef();
      (void)moho::register_EntityAddManualScroller_LuaFuncDef();
      (void)moho::register_EntityAddThreadScroller_LuaFuncDef();
      (void)moho::register_EntityAddPingPongScroller_LuaFuncDef();
      (void)moho::register_EntityRemoveScroller_LuaFuncDef();
      (void)moho::register_EntityDestroy_LuaFuncDef();
      (void)moho::register_EntityBeenDestroyed_LuaFuncDef();
      (void)moho::register_EntityKill_LuaFuncDef();
      (void)moho::register__c_CreateEntity_LuaFuncDef();
      (void)moho::register_EntityFallDown_LuaFuncDef();
      (void)moho::j_func_MotorFallDownWhack_LuaFuncDef();
      (void)moho::j_func_EntitySinkAway_LuaFuncDef();
    }
  };

  [[maybe_unused]] EntityLuaFunctionThunksBootstrap gEntityLuaFunctionThunksBootstrap;
} // namespace
