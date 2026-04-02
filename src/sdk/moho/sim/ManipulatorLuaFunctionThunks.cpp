#include "moho/sim/ManipulatorLuaFunctionThunks.h"

#include "moho/lua/CScrLuaInitForm.h"

namespace
{
  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardManipulatorLuaThunk() noexcept
  {
    return Target();
  }

  struct ManipulatorLuaFunctionThunksBootstrap
  {
    ManipulatorLuaFunctionThunksBootstrap()
    {
      (void)moho::j_func_CreateAimController_LuaFuncDef();
      (void)moho::register_CAimManipulatorSetFiringArc_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorSetResetPoseTime_LuaFuncDef();
      (void)moho::register_CAimManipulatorOnTarget_LuaFuncDef();
      (void)moho::register_CAimManipulatorSetEnabled_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorGetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorSetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef();
      (void)moho::j_func_CBoneEntityManipulatorSetPivot_LuaFuncDef();
      (void)moho::register_EntityAttachBoneToEntityBone_LuaFuncDef();
      (void)moho::j_func_CreateBuilderArmController_LuaFuncDef();
      (void)moho::j_func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef();
      (void)moho::j_func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CreateCollisionDetector_LuaFuncDef();
      (void)moho::j_func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef();
      (void)moho::j_func_CCollisionManipulatorEnable_LuaFuncDef();
      (void)moho::register_CCollisionManipulatorDisable_LuaFuncDef();
      (void)moho::j_func_CCollisionManipulatorWatchBone_LuaFuncDef();
      (void)moho::register_CreateFootPlantController_LuaFuncDef();
      (void)moho::j_func_IAniManipulatorSetPrecedence_LuaFuncDef();
      (void)moho::register_IAniManipulatorEnable_LuaFuncDef();
      (void)moho::register_IAniManipulatorDisable_LuaFuncDef();
      (void)moho::j_func_IAniManipulatorDestroy_LuaFuncDef();
      (void)moho::j_func_CreateAnimator_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorPlayAnim_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetRate_LuaFuncDef();
      (void)moho::j_func_CAnimationManipulatorSetRate_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetAnimationFraction_LuaFuncDef();
      (void)moho::j_func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetAnimationTime_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetAnimationTime_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetAnimationDuration_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetBoneEnabled_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetOverwriteMode_LuaFuncDef();
      (void)moho::j_func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef();
      (void)moho::j_func_CreateRotator_LuaFuncDef();
      (void)moho::register_CRotateManipulatorSetSpinDown_LuaFuncDef();
      (void)moho::register_CRotateManipulatorSetGoal_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorClearGoal_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetSpeed_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetTargetSpeed_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetAccel_LuaFuncDef();
      (void)moho::register_CRotateManipulatorClearFollowBone_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetFollowBone_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorGetCurrentAngle_LuaFuncDef();
      (void)moho::register_CRotateManipulatorSetCurrentAngle_LuaFuncDef();
      (void)moho::j_func_CreateSlaver_LuaFuncDef();
      (void)moho::register_CSlaveManipulatorSetMaxRate_LuaFuncDef();
      (void)moho::j_func_CreateSlider_LuaFuncDef();
      (void)moho::register_CSlideManipulatorSetWorldUnits_LuaFuncDef();
      (void)moho::register_CSlideManipulatorSetSpeed_LuaFuncDef();
      (void)moho::j_func_CSlideManipulatorSetAcceleration_LuaFuncDef();
      (void)moho::register_CSlideManipulatorSetDeceleration_LuaFuncDef();
      (void)moho::j_func_CSlideManipulatorSetGoal_LuaFuncDef();
      (void)moho::register_CSlideManipulatorBeenDestroyed_LuaFuncDef();
      (void)moho::j_func_CreateStorageManip_LuaFuncDef();
      (void)moho::j_func_CreateThrustController_LuaFuncDef();
      (void)moho::j_func_CThrustManipulatorSetThrustingParam_LuaFuncDef();
    }
  };

  [[maybe_unused]] ManipulatorLuaFunctionThunksBootstrap gManipulatorLuaFunctionThunksBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD22D0 (FUN_00BD22D0, j_func_CreateAimController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateAimController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateAimController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateAimController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD22E0 (FUN_00BD22E0, register_CAimManipulatorSetFiringArc_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetFiringArc_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorSetFiringArc_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetFiringArc_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD22F0 (FUN_00BD22F0, j_func_CAimManipulatorSetResetPoseTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetResetPoseTime_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetResetPoseTime_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetResetPoseTime_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2300 (FUN_00BD2300, register_CAimManipulatorOnTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorOnTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorOnTarget_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorOnTarget_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2310 (FUN_00BD2310, register_CAimManipulatorSetEnabled_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetEnabled_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorSetEnabled_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetEnabled_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2320 (FUN_00BD2320, j_func_CAimManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorGetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorGetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorGetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2330 (FUN_00BD2330, j_func_CAimManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2340 (FUN_00BD2340, j_func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD24A0 (FUN_00BD24A0, j_func_CBoneEntityManipulatorSetPivot_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBoneEntityManipulatorSetPivot_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBoneEntityManipulatorSetPivot_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBoneEntityManipulatorSetPivot_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD24B0 (FUN_00BD24B0, register_EntityAttachBoneToEntityBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_EntityAttachBoneToEntityBone_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityAttachBoneToEntityBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_EntityAttachBoneToEntityBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD25F0 (FUN_00BD25F0, j_func_CreateBuilderArmController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateBuilderArmController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateBuilderArmController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateBuilderArmController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2600 (FUN_00BD2600, j_func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2610 (FUN_00BD2610, j_func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2620 (FUN_00BD2620, j_func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2A60 (FUN_00BD2A60, register_CreateFootPlantController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateFootPlantController_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CreateFootPlantController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateFootPlantController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2C80 (FUN_00BD2C80, j_func_IAniManipulatorSetPrecedence_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorSetPrecedence_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IAniManipulatorSetPrecedence_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorSetPrecedence_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2C90 (FUN_00BD2C90, register_IAniManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorEnable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IAniManipulatorEnable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorEnable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2CA0 (FUN_00BD2CA0, register_IAniManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorDisable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IAniManipulatorDisable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorDisable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2CB0 (FUN_00BD2CB0, j_func_IAniManipulatorDestroy_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorDestroy_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IAniManipulatorDestroy_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorDestroy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2760 (FUN_00BD2760, j_func_CreateCollisionDetector_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateCollisionDetector_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateCollisionDetector_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateCollisionDetector_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2770 (FUN_00BD2770, j_func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2780 (FUN_00BD2780, j_func_CCollisionManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorEnable_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorEnable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorEnable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2790 (FUN_00BD2790, register_CCollisionManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorDisable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CCollisionManipulatorDisable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorDisable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD27A0 (FUN_00BD27A0, j_func_CCollisionManipulatorWatchBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorWatchBone_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorWatchBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorWatchBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E30 (FUN_00BD2E30, j_func_CreateAnimator_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateAnimator_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateAnimator_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateAnimator_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E40 (FUN_00BD2E40, register_CAnimationManipulatorPlayAnim_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorPlayAnim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorPlayAnim_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorPlayAnim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E50 (FUN_00BD2E50, register_CAnimationManipulatorGetRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetRate_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetRate_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetRate_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E60 (FUN_00BD2E60, j_func_CAnimationManipulatorSetRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetRate_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetRate_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetRate_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E70 (FUN_00BD2E70, register_CAnimationManipulatorGetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationFraction_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E80 (FUN_00BD2E80, j_func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E90 (FUN_00BD2E90, register_CAnimationManipulatorGetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationTime_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationTime_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetAnimationTime_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EA0 (FUN_00BD2EA0, register_CAnimationManipulatorSetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetAnimationTime_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetAnimationTime_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetAnimationTime_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EB0 (FUN_00BD2EB0, register_CAnimationManipulatorGetAnimationDuration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationDuration_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EC0 (FUN_00BD2EC0, register_CAnimationManipulatorSetBoneEnabled_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetBoneEnabled_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2ED0 (FUN_00BD2ED0, register_CAnimationManipulatorSetOverwriteMode_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetOverwriteMode_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EE0 (FUN_00BD2EE0, j_func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EF0 (FUN_00BD2EF0, register_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3050 (FUN_00BD3050, j_func_CreateRotator_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateRotator_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateRotator_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateRotator_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3060 (FUN_00BD3060, register_CRotateManipulatorSetSpinDown_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetSpinDown_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetSpinDown_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetSpinDown_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3070 (FUN_00BD3070, register_CRotateManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetGoal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetGoal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3080 (FUN_00BD3080, j_func_CRotateManipulatorClearGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorClearGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorClearGoal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorClearGoal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3090 (FUN_00BD3090, j_func_CRotateManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetSpeed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetSpeed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30A0 (FUN_00BD30A0, j_func_CRotateManipulatorSetTargetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetTargetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetTargetSpeed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetTargetSpeed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30B0 (FUN_00BD30B0, j_func_CRotateManipulatorSetAccel_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetAccel_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetAccel_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetAccel_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30C0 (FUN_00BD30C0, register_CRotateManipulatorClearFollowBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorClearFollowBone_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorClearFollowBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorClearFollowBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30D0 (FUN_00BD30D0, j_func_CRotateManipulatorSetFollowBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetFollowBone_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetFollowBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetFollowBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30E0 (FUN_00BD30E0, j_func_CRotateManipulatorGetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorGetCurrentAngle_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorGetCurrentAngle_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorGetCurrentAngle_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30F0 (FUN_00BD30F0, register_CRotateManipulatorSetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetCurrentAngle_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetCurrentAngle_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetCurrentAngle_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3230 (FUN_00BD3230, j_func_CreateSlaver_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateSlaver_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateSlaver_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateSlaver_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3240 (FUN_00BD3240, register_CSlaveManipulatorSetMaxRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlaveManipulatorSetMaxRate_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlaveManipulatorSetMaxRate_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlaveManipulatorSetMaxRate_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3500 (FUN_00BD3500, j_func_CreateSlider_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateSlider_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateSlider_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateSlider_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3510 (FUN_00BD3510, register_CSlideManipulatorSetWorldUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetWorldUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetWorldUnits_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetWorldUnits_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3520 (FUN_00BD3520, register_CSlideManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetSpeed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetSpeed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3530 (FUN_00BD3530, j_func_CSlideManipulatorSetAcceleration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetAcceleration_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CSlideManipulatorSetAcceleration_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetAcceleration_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3540 (FUN_00BD3540, register_CSlideManipulatorSetDeceleration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetDeceleration_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetDeceleration_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetDeceleration_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3550 (FUN_00BD3550, j_func_CSlideManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CSlideManipulatorSetGoal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetGoal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3560 (FUN_00BD3560, register_CSlideManipulatorBeenDestroyed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorBeenDestroyed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorBeenDestroyed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorBeenDestroyed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD36A0 (FUN_00BD36A0, j_func_CreateStorageManip_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateStorageManip_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateStorageManip_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateStorageManip_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD37E0 (FUN_00BD37E0, j_func_CreateThrustController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateThrustController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateThrustController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateThrustController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD37F0 (FUN_00BD37F0, j_func_CThrustManipulatorSetThrustingParam_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CThrustManipulatorSetThrustingParam_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CThrustManipulatorSetThrustingParam_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CThrustManipulatorSetThrustingParam_LuaFuncDef>();
  }
} // namespace moho
