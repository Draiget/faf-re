#pragma once

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

struct lua_State;

namespace moho
{
  class CScrLuaInitForm;

  // Underlying Lua function-definition publishers referenced by this thunk pack.
  /**
   * Address: 0x00631F40 (FUN_00631F40, func_CreateAimController_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateAimController(...)` Lua binder.
   */
  CScrLuaInitForm* func_CreateAimController_LuaFuncDef();
  CScrLuaInitForm* func_CAimManipulatorSetFiringArc_LuaFuncDef();
  CScrLuaInitForm* func_CAimManipulatorSetResetPoseTime_LuaFuncDef();
  CScrLuaInitForm* func_CAimManipulatorOnTarget_LuaFuncDef();
  CScrLuaInitForm* func_CAimManipulatorSetEnabled_LuaFuncDef();
  CScrLuaInitForm* func_CAimManipulatorGetHeadingPitch_LuaFuncDef();
  CScrLuaInitForm* func_CAimManipulatorSetHeadingPitch_LuaFuncDef();
  CScrLuaInitForm* func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef();

  /**
   * Address: 0x00639CA0 (FUN_00639CA0, func_CreateFootPlantController_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateFootPlantController(...)` Lua binder.
   */
  CScrLuaInitForm* func_CreateFootPlantController_LuaFuncDef();

  /**
   * Address: 0x00636820 (FUN_00636820, func_CreateBuilderArmController_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateBuilderArmController(...)` Lua binder.
   */
  CScrLuaInitForm* func_CreateBuilderArmController_LuaFuncDef();

  /**
   * Address: 0x006371B0 (FUN_006371B0, func_CreateLuaBuilderArmObject)
   *
   * What it does:
   * Builds the cached `CBuilderArmManipulator` Lua metatable object into the
   * caller-provided destination.
   */
  LuaPlus::LuaObject* func_CreateLuaBuilderArmObject(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00633050 (FUN_00633050, func_CreateLuaAimManipulatorObject)
   *
   * What it does:
   * Builds the cached `CAimManipulator` Lua metatable object into the
   * caller-provided destination.
   */
  LuaPlus::LuaObject* func_CreateLuaAimManipulatorObject(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * Address: 0x006352F0 (FUN_006352F0, func_CreateLuaBoneEntityManipulatorObject)
   *
   * What it does:
   * Builds the cached `CBoneEntityManipulator` Lua metatable object into the
   * caller-provided destination.
   */
  LuaPlus::LuaObject* func_CreateLuaBoneEntityManipulatorObject(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * Address: 0x0063A1D0 (FUN_0063A1D0, func_CreateLuaFootPlantManipulatorObject)
   *
   * What it does:
   * Builds the cached `CFootPlantManipulator` Lua metatable object into the
   * caller-provided destination.
   */
  LuaPlus::LuaObject* func_CreateLuaFootPlantManipulatorObject(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00634C90 (FUN_00634C90, func_CBoneEntityManipulatorSetPivot_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBoneEntityManipulator:SetPivot(x, y, z)` Lua binder.
   */
  CScrLuaInitForm* func_CBoneEntityManipulatorSetPivot_LuaFuncDef();

  /**
   * Address: 0x00634EA0 (FUN_00634EA0, func_EntityAttachBoneToEntityBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AttachBoneToEntityBone(...)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAttachBoneToEntityBone_LuaFuncDef();

  /**
   * Address: 0x006369F0 (FUN_006369F0, func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBuilderArmManipulator:SetAimingArc(...)` Lua binder.
   */
  CScrLuaInitForm* func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef();

  /**
   * Address: 0x00636BF0 (FUN_00636BF0, func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBuilderArmManipulator:GetHeadingPitch()` Lua binder.
   */
  CScrLuaInitForm* func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef();

  /**
   * Address: 0x00636D50 (FUN_00636D50, func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBuilderArmManipulator:SetHeadingPitch(heading, pitch)` Lua
   * binder.
   */
  CScrLuaInitForm* func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef();
  CScrLuaInitForm* func_IAniManipulatorSetPrecedence_LuaFuncDef();
  CScrLuaInitForm* func_IAniManipulatorEnable_LuaFuncDef();
  CScrLuaInitForm* func_IAniManipulatorDisable_LuaFuncDef();
  CScrLuaInitForm* func_IAniManipulatorDestroy_LuaFuncDef();
  CScrLuaInitForm* func_CreateAnimator_LuaFuncDef();

  /**
   * Address: 0x00640690 (FUN_00640690, func_CAnimationManipulatorPlayAnim_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:PlayAnim(...)` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorPlayAnim_LuaFuncDef();
  CScrLuaInitForm* func_CAnimationManipulatorGetRate_LuaFuncDef();
  CScrLuaInitForm* func_CAnimationManipulatorSetRate_LuaFuncDef();
  CScrLuaInitForm* func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef();
  CScrLuaInitForm* func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef();
  CScrLuaInitForm* func_CAnimationManipulatorGetAnimationTime_LuaFuncDef();
  CScrLuaInitForm* func_CAnimationManipulatorSetAnimationTime_LuaFuncDef();
  CScrLuaInitForm* func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef();
  CScrLuaInitForm* func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef();
  CScrLuaInitForm* func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef();
  CScrLuaInitForm* func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef();
  CScrLuaInitForm* func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef();

  /**
   * Address: 0x006445E0 (FUN_006445E0, func_CRotateManipulatorClearGoal_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:ClearGoal()` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorClearGoal_LuaFuncDef();
  CScrLuaInitForm* func_CreateRotator_LuaFuncDef();
  /**
   * Address: 0x00645540 (FUN_00645540, func_CreateCRotateManipulatorObject)
   *
   * What it does:
   * Builds the cached `CRotateManipulator` Lua metatable object into the
   * caller-provided destination.
   */
  LuaPlus::LuaObject* func_CreateCRotateManipulatorObject(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * Address: 0x006442A0 (FUN_006442A0, func_CRotateManipulatorSetSpinDown_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetSpinDown(flag)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetSpinDown_LuaFuncDef();

  /**
   * Address: 0x00644410 (FUN_00644410, func_CRotateManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetGoal(degrees)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetGoal_LuaFuncDef();

  /**
   * Address: 0x00644730 (FUN_00644730, func_CRotateManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetSpeed(...)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetSpeed_LuaFuncDef();

  /**
   * Address: 0x006448D0 (FUN_006448D0, func_CRotateManipulatorSetTargetSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetTargetSpeed(...)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetTargetSpeed_LuaFuncDef();

  /**
   * Address: 0x00644AA0 (FUN_00644AA0, func_CRotateManipulatorSetAccel_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetAccel(...)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetAccel_LuaFuncDef();

  /**
   * Address: 0x00644C40 (FUN_00644C40, func_CRotateManipulatorClearFollowBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:ClearFollowBone()` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorClearFollowBone_LuaFuncDef();

  /**
   * Address: 0x00644DB0 (FUN_00644DB0, func_CRotateManipulatorSetFollowBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetFollowBone(bone)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetFollowBone_LuaFuncDef();

  /**
   * Address: 0x00644F50 (FUN_00644F50, func_CRotateManipulatorGetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:GetCurrentAngle()` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorGetCurrentAngle_LuaFuncDef();

  /**
   * Address: 0x006450C0 (FUN_006450C0, func_CRotateManipulatorSetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetCurrentAngle(angle)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetCurrentAngle_LuaFuncDef();
  CScrLuaInitForm* func_CreateSlaver_LuaFuncDef();
  CScrLuaInitForm* func_CSlaveManipulatorSetMaxRate_LuaFuncDef();
  CScrLuaInitForm* func_CreateSlider_LuaFuncDef();
  CScrLuaInitForm* func_CSlideManipulatorSetWorldUnits_LuaFuncDef();
  CScrLuaInitForm* func_CSlideManipulatorSetSpeed_LuaFuncDef();
  CScrLuaInitForm* func_CSlideManipulatorSetAcceleration_LuaFuncDef();
  CScrLuaInitForm* func_CSlideManipulatorSetDeceleration_LuaFuncDef();
  CScrLuaInitForm* func_CSlideManipulatorSetGoal_LuaFuncDef();
  CScrLuaInitForm* func_CSlideManipulatorBeenDestroyed_LuaFuncDef();
  CScrLuaInitForm* func_CreateStorageManip_LuaFuncDef();

  /**
   * Address: 0x0064AB60 (FUN_0064AB60, func_CreateThrustController_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateThrustController(...)` Lua binder.
   */
  CScrLuaInitForm* func_CreateThrustController_LuaFuncDef();
  /**
   * Address: 0x0064B380 (FUN_0064B380, func_CreateLuaCThrustManipulator)
   *
   * What it does:
   * Builds the cached `CThrustManipulator` Lua metatable object into the
   * caller-provided destination.
   */
  LuaPlus::LuaObject* func_CreateLuaCThrustManipulator(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * What it does:
   * Returns the cached metatable object used for `CRotateManipulator` Lua
   * userdata construction paths.
   */
  LuaPlus::LuaObject CreateRotateManipulatorLuaMetatable(LuaPlus::LuaState* state);

  /**
   * Address: 0x0064AD30 (FUN_0064AD30, func_CThrustManipulatorSetThrustingParam_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CThrustManipulator:SetThrustingParam(...)` Lua binder.
   */
  CScrLuaInitForm* func_CThrustManipulatorSetThrustingParam_LuaFuncDef();

  /**
   * Address: 0x0064AD10 (FUN_0064AD10, cfunc_CThrustManipulatorSetThrustingParam)
   *
   * What it does:
   * Unwraps raw Lua callback state and forwards to
   * `cfunc_CThrustManipulatorSetThrustingParamL`.
   */
  int cfunc_CThrustManipulatorSetThrustingParam(lua_State* luaContext);

  /**
   * Address: 0x0064AD90 (FUN_0064AD90, cfunc_CThrustManipulatorSetThrustingParamL)
   *
   * What it does:
   * Validates and reads thrust-cap/turn parameters from Lua, then writes them
   * to one `CThrustManipulator` runtime lane.
   */
  int cfunc_CThrustManipulatorSetThrustingParamL(LuaPlus::LuaState* state);
  CScrLuaInitForm* func_CreateCollisionDetector_LuaFuncDef();
  CScrLuaInitForm* func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef();
  CScrLuaInitForm* func_CCollisionManipulatorEnable_LuaFuncDef();
  CScrLuaInitForm* func_CCollisionManipulatorDisable_LuaFuncDef();
  CScrLuaInitForm* func_CCollisionManipulatorWatchBone_LuaFuncDef();

  /**
   * Address: 0x00BD22D0 (FUN_00BD22D0, j_func_CreateAimController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateAimController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateAimController_LuaFuncDef();

  /**
   * Address: 0x00BD22E0 (FUN_00BD22E0, register_CAimManipulatorSetFiringArc_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetFiringArc_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorSetFiringArc_LuaFuncDef();

  /**
   * Address: 0x00BD22F0 (FUN_00BD22F0, j_func_CAimManipulatorSetResetPoseTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetResetPoseTime_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetResetPoseTime_LuaFuncDef();

  /**
   * Address: 0x00BD2300 (FUN_00BD2300, register_CAimManipulatorOnTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorOnTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorOnTarget_LuaFuncDef();

  /**
   * Address: 0x00BD2310 (FUN_00BD2310, register_CAimManipulatorSetEnabled_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetEnabled_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorSetEnabled_LuaFuncDef();

  /**
   * Address: 0x00BD2320 (FUN_00BD2320, j_func_CAimManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorGetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorGetHeadingPitch_LuaFuncDef();

  /**
   * Address: 0x00BD2330 (FUN_00BD2330, j_func_CAimManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetHeadingPitch_LuaFuncDef();

  /**
   * Address: 0x00BD2340 (FUN_00BD2340, j_func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef();

  /**
   * Address: 0x00BD24A0 (FUN_00BD24A0, j_func_CBoneEntityManipulatorSetPivot_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBoneEntityManipulatorSetPivot_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBoneEntityManipulatorSetPivot_LuaFuncDef();

  /**
   * Address: 0x00BD24B0 (FUN_00BD24B0, register_EntityAttachBoneToEntityBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_EntityAttachBoneToEntityBone_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityAttachBoneToEntityBone_LuaFuncDef();

  /**
   * Address: 0x00BD25F0 (FUN_00BD25F0, j_func_CreateBuilderArmController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateBuilderArmController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateBuilderArmController_LuaFuncDef();

  /**
   * Address: 0x00BD2600 (FUN_00BD2600, j_func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef();

  /**
   * Address: 0x00BD2610 (FUN_00BD2610, j_func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef();

  /**
   * Address: 0x00BD2620 (FUN_00BD2620, j_func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef();

  /**
   * Address: 0x00BD2760 (FUN_00BD2760, j_func_CreateCollisionDetector_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateCollisionDetector_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateCollisionDetector_LuaFuncDef();

  /**
   * Address: 0x00BD2770 (FUN_00BD2770, j_func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef();

  /**
   * Address: 0x00BD2780 (FUN_00BD2780, j_func_CCollisionManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorEnable_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorEnable_LuaFuncDef();

  /**
   * Address: 0x00BD2790 (FUN_00BD2790, register_CCollisionManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorDisable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CCollisionManipulatorDisable_LuaFuncDef();

  /**
   * Address: 0x00BD27A0 (FUN_00BD27A0, j_func_CCollisionManipulatorWatchBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorWatchBone_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorWatchBone_LuaFuncDef();

  /**
   * Address: 0x00BD2A60 (FUN_00BD2A60, register_CreateFootPlantController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateFootPlantController_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CreateFootPlantController_LuaFuncDef();

  /**
   * Address: 0x00BD2C80 (FUN_00BD2C80, j_func_IAniManipulatorSetPrecedence_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorSetPrecedence_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IAniManipulatorSetPrecedence_LuaFuncDef();

  /**
   * Address: 0x00BD2C90 (FUN_00BD2C90, register_IAniManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorEnable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IAniManipulatorEnable_LuaFuncDef();

  /**
   * Address: 0x00BD2CA0 (FUN_00BD2CA0, register_IAniManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorDisable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IAniManipulatorDisable_LuaFuncDef();

  /**
   * Address: 0x00BD2CB0 (FUN_00BD2CB0, j_func_IAniManipulatorDestroy_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorDestroy_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IAniManipulatorDestroy_LuaFuncDef();

  /**
   * Address: 0x00BD2E30 (FUN_00BD2E30, j_func_CreateAnimator_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateAnimator_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateAnimator_LuaFuncDef();

  /**
   * Address: 0x00BD2E40 (FUN_00BD2E40, register_CAnimationManipulatorPlayAnim_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorPlayAnim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorPlayAnim_LuaFuncDef();

  /**
   * Address: 0x00BD2E50 (FUN_00BD2E50, register_CAnimationManipulatorGetRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetRate_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetRate_LuaFuncDef();

  /**
   * Address: 0x00BD2E60 (FUN_00BD2E60, j_func_CAnimationManipulatorSetRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetRate_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetRate_LuaFuncDef();

  /**
   * Address: 0x00BD2E70 (FUN_00BD2E70, register_CAnimationManipulatorGetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationFraction_LuaFuncDef();

  /**
   * Address: 0x00BD2E80 (FUN_00BD2E80, j_func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef();

  /**
   * Address: 0x00BD2E90 (FUN_00BD2E90, register_CAnimationManipulatorGetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationTime_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationTime_LuaFuncDef();

  /**
   * Address: 0x00BD2EA0 (FUN_00BD2EA0, register_CAnimationManipulatorSetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetAnimationTime_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetAnimationTime_LuaFuncDef();

  /**
   * Address: 0x00BD2EB0 (FUN_00BD2EB0, register_CAnimationManipulatorGetAnimationDuration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationDuration_LuaFuncDef();

  /**
   * Address: 0x00BD2EC0 (FUN_00BD2EC0, register_CAnimationManipulatorSetBoneEnabled_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetBoneEnabled_LuaFuncDef();

  /**
   * Address: 0x00BD2ED0 (FUN_00BD2ED0, register_CAnimationManipulatorSetOverwriteMode_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetOverwriteMode_LuaFuncDef();

  /**
   * Address: 0x00BD2EE0 (FUN_00BD2EE0, j_func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef();

  /**
   * Address: 0x00BD2EF0 (FUN_00BD2EF0, register_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef();

  /**
   * Address: 0x00BD3050 (FUN_00BD3050, j_func_CreateRotator_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateRotator_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateRotator_LuaFuncDef();

  /**
   * Address: 0x00BD3060 (FUN_00BD3060, register_CRotateManipulatorSetSpinDown_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetSpinDown_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetSpinDown_LuaFuncDef();

  /**
   * Address: 0x00BD3070 (FUN_00BD3070, register_CRotateManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetGoal_LuaFuncDef();

  /**
   * Address: 0x00BD3080 (FUN_00BD3080, j_func_CRotateManipulatorClearGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorClearGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorClearGoal_LuaFuncDef();

  /**
   * Address: 0x00BD3090 (FUN_00BD3090, j_func_CRotateManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetSpeed_LuaFuncDef();

  /**
   * Address: 0x00BD30A0 (FUN_00BD30A0, j_func_CRotateManipulatorSetTargetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetTargetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetTargetSpeed_LuaFuncDef();

  /**
   * Address: 0x00BD30B0 (FUN_00BD30B0, j_func_CRotateManipulatorSetAccel_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetAccel_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetAccel_LuaFuncDef();

  /**
   * Address: 0x00BD30C0 (FUN_00BD30C0, register_CRotateManipulatorClearFollowBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorClearFollowBone_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorClearFollowBone_LuaFuncDef();

  /**
   * Address: 0x00BD30D0 (FUN_00BD30D0, j_func_CRotateManipulatorSetFollowBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetFollowBone_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetFollowBone_LuaFuncDef();

  /**
   * Address: 0x00BD30E0 (FUN_00BD30E0, j_func_CRotateManipulatorGetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorGetCurrentAngle_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorGetCurrentAngle_LuaFuncDef();

  /**
   * Address: 0x00BD30F0 (FUN_00BD30F0, register_CRotateManipulatorSetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetCurrentAngle_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetCurrentAngle_LuaFuncDef();

  /**
   * Address: 0x00BD3230 (FUN_00BD3230, j_func_CreateSlaver_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateSlaver_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateSlaver_LuaFuncDef();

  /**
   * Address: 0x00BD3240 (FUN_00BD3240, register_CSlaveManipulatorSetMaxRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlaveManipulatorSetMaxRate_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlaveManipulatorSetMaxRate_LuaFuncDef();

  /**
   * Address: 0x00BD3500 (FUN_00BD3500, j_func_CreateSlider_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateSlider_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateSlider_LuaFuncDef();

  /**
   * Address: 0x00BD3510 (FUN_00BD3510, register_CSlideManipulatorSetWorldUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetWorldUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetWorldUnits_LuaFuncDef();

  /**
   * Address: 0x00BD3520 (FUN_00BD3520, register_CSlideManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetSpeed_LuaFuncDef();

  /**
   * Address: 0x00BD3530 (FUN_00BD3530, j_func_CSlideManipulatorSetAcceleration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetAcceleration_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CSlideManipulatorSetAcceleration_LuaFuncDef();

  /**
   * Address: 0x00BD3540 (FUN_00BD3540, register_CSlideManipulatorSetDeceleration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetDeceleration_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetDeceleration_LuaFuncDef();

  /**
   * Address: 0x00BD3550 (FUN_00BD3550, j_func_CSlideManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CSlideManipulatorSetGoal_LuaFuncDef();

  /**
   * Address: 0x00BD3560 (FUN_00BD3560, register_CSlideManipulatorBeenDestroyed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorBeenDestroyed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorBeenDestroyed_LuaFuncDef();

  /**
   * Address: 0x00BD36A0 (FUN_00BD36A0, j_func_CreateStorageManip_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateStorageManip_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateStorageManip_LuaFuncDef();

  /**
   * Address: 0x00BD37E0 (FUN_00BD37E0, j_func_CreateThrustController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateThrustController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateThrustController_LuaFuncDef();

  /**
   * Address: 0x00BD37F0 (FUN_00BD37F0, j_func_CThrustManipulatorSetThrustingParam_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CThrustManipulatorSetThrustingParam_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CThrustManipulatorSetThrustingParam_LuaFuncDef();
} // namespace moho
