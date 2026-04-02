#include "moho/lua/CScrLuaInitForm.h"

namespace
{
  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardProjectileLuaThunk() noexcept
  {
    return Target();
  }
} // namespace

namespace moho
{
  CScrLuaInitForm* func_ProjectileGetLauncher_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileGetTrackingTarget_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileGetCurrentTargetPosition_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetNewTarget_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetNewTargetGround_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetLifetime_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetDamage_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetMaxSpeed_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetAcceleration_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetBallisticAcceleration_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetDestroyOnWater_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetTurnRate_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileGetCurrentSpeed_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileGetVelocity_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetVelocity_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetScaleVelocity_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetLocalAngularVelocity_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetCollision_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetCollideSurface_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetCollideEntity_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileStayUnderwater_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileTrackTarget_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetStayUpright_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetVelocityAlign_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileCreateChildProjectile_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileSetVelocityRandomUpVector_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileChangeMaxZigZag_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileChangeZigZagFrequency_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileChangeDetonateAboveHeight_LuaFuncDef();
  CScrLuaInitForm* func_ProjectileChangeDetonateBelowHeight_LuaFuncDef();

  /**
   * Address: 0x00BD6620 (FUN_00BD6620, register_ProjectileGetLauncher_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileGetLauncher_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileGetLauncher_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6630 (FUN_00BD6630, register_ProjectileGetTrackingTarget_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileGetTrackingTarget_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileGetTrackingTarget_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6640 (FUN_00BD6640, register_ProjectileGetCurrentTargetPosition_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileGetCurrentTargetPosition_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileGetCurrentTargetPosition_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6650 (FUN_00BD6650, register_ProjectileSetNewTarget_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetNewTarget_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetNewTarget_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6660 (FUN_00BD6660, register_ProjectileSetNewTargetGround_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetNewTargetGround_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetNewTargetGround_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6670 (FUN_00BD6670, register_ProjectileSetLifetime_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetLifetime_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetLifetime_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6680 (FUN_00BD6680, register_ProjectileSetDamage_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetDamage_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetDamage_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6690 (FUN_00BD6690, register_ProjectileSetMaxSpeed_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetMaxSpeed_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetMaxSpeed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD66A0 (FUN_00BD66A0, register_ProjectileSetAcceleration_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetAcceleration_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetAcceleration_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD66B0 (FUN_00BD66B0, register_ProjectileSetBallisticAcceleration_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetBallisticAcceleration_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetBallisticAcceleration_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD66C0 (FUN_00BD66C0, register_ProjectileSetDestroyOnWater_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetDestroyOnWater_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetDestroyOnWater_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD66D0 (FUN_00BD66D0, register_ProjectileSetTurnRate_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetTurnRate_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetTurnRate_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD66E0 (FUN_00BD66E0, j_func_ProjectileGetCurrentSpeed_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_ProjectileGetCurrentSpeed_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileGetCurrentSpeed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD66F0 (FUN_00BD66F0, register_ProjectileGetVelocity_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileGetVelocity_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileGetVelocity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6700 (FUN_00BD6700, register_ProjectileSetVelocity_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetVelocity_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetVelocity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6710 (FUN_00BD6710, register_ProjectileSetScaleVelocity_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetScaleVelocity_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetScaleVelocity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6720 (FUN_00BD6720, j_func_ProjectileSetLocalAngularVelocity_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_ProjectileSetLocalAngularVelocity_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetLocalAngularVelocity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6730 (FUN_00BD6730, j_func_ProjectileSetCollision_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_ProjectileSetCollision_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetCollision_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6740 (FUN_00BD6740, register_ProjectileSetCollideSurface_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetCollideSurface_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetCollideSurface_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6750 (FUN_00BD6750, register_ProjectileSetCollideEntity_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetCollideEntity_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetCollideEntity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6760 (FUN_00BD6760, register_ProjectileStayUnderwater_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileStayUnderwater_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileStayUnderwater_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6770 (FUN_00BD6770, register_ProjectileTrackTarget_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileTrackTarget_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileTrackTarget_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6780 (FUN_00BD6780, register_ProjectileSetStayUpright_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetStayUpright_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetStayUpright_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD6790 (FUN_00BD6790, register_ProjectileSetVelocityAlign_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetVelocityAlign_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetVelocityAlign_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD67A0 (FUN_00BD67A0, j_func_ProjectileCreateChildProjectile_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_ProjectileCreateChildProjectile_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileCreateChildProjectile_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD67B0 (FUN_00BD67B0, register_ProjectileSetVelocityRandomUpVector_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileSetVelocityRandomUpVector_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileSetVelocityRandomUpVector_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD67C0 (FUN_00BD67C0, j_func_ProjectileChangeMaxZigZag_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_ProjectileChangeMaxZigZag_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileChangeMaxZigZag_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD67D0 (FUN_00BD67D0, register_ProjectileChangeZigZagFrequency_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileChangeZigZagFrequency_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileChangeZigZagFrequency_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD67E0 (FUN_00BD67E0, register_ProjectileChangeDetonateAboveHeight_LuaFuncDef)
   */
  CScrLuaInitForm* register_ProjectileChangeDetonateAboveHeight_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileChangeDetonateAboveHeight_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD67F0 (FUN_00BD67F0, j_func_ProjectileChangeDetonateBelowHeight_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_ProjectileChangeDetonateBelowHeight_LuaFuncDef()
  {
    return ForwardProjectileLuaThunk<&func_ProjectileChangeDetonateBelowHeight_LuaFuncDef>();
  }
} // namespace moho

namespace
{
  struct ProjectileLuaFunctionThunksBootstrap
  {
    ProjectileLuaFunctionThunksBootstrap()
    {
      (void)moho::register_ProjectileGetLauncher_LuaFuncDef();
      (void)moho::register_ProjectileGetTrackingTarget_LuaFuncDef();
      (void)moho::register_ProjectileGetCurrentTargetPosition_LuaFuncDef();
      (void)moho::register_ProjectileSetNewTarget_LuaFuncDef();
      (void)moho::register_ProjectileSetNewTargetGround_LuaFuncDef();
      (void)moho::register_ProjectileSetLifetime_LuaFuncDef();
      (void)moho::register_ProjectileSetDamage_LuaFuncDef();
      (void)moho::register_ProjectileSetMaxSpeed_LuaFuncDef();
      (void)moho::register_ProjectileSetAcceleration_LuaFuncDef();
      (void)moho::register_ProjectileSetBallisticAcceleration_LuaFuncDef();
      (void)moho::register_ProjectileSetDestroyOnWater_LuaFuncDef();
      (void)moho::register_ProjectileSetTurnRate_LuaFuncDef();
      (void)moho::j_func_ProjectileGetCurrentSpeed_LuaFuncDef();
      (void)moho::register_ProjectileGetVelocity_LuaFuncDef();
      (void)moho::register_ProjectileSetVelocity_LuaFuncDef();
      (void)moho::register_ProjectileSetScaleVelocity_LuaFuncDef();
      (void)moho::j_func_ProjectileSetLocalAngularVelocity_LuaFuncDef();
      (void)moho::j_func_ProjectileSetCollision_LuaFuncDef();
      (void)moho::register_ProjectileSetCollideSurface_LuaFuncDef();
      (void)moho::register_ProjectileSetCollideEntity_LuaFuncDef();
      (void)moho::register_ProjectileStayUnderwater_LuaFuncDef();
      (void)moho::register_ProjectileTrackTarget_LuaFuncDef();
      (void)moho::register_ProjectileSetStayUpright_LuaFuncDef();
      (void)moho::register_ProjectileSetVelocityAlign_LuaFuncDef();
      (void)moho::j_func_ProjectileCreateChildProjectile_LuaFuncDef();
      (void)moho::register_ProjectileSetVelocityRandomUpVector_LuaFuncDef();
      (void)moho::j_func_ProjectileChangeMaxZigZag_LuaFuncDef();
      (void)moho::register_ProjectileChangeZigZagFrequency_LuaFuncDef();
      (void)moho::register_ProjectileChangeDetonateAboveHeight_LuaFuncDef();
      (void)moho::j_func_ProjectileChangeDetonateBelowHeight_LuaFuncDef();
    }
  };

  [[maybe_unused]] ProjectileLuaFunctionThunksBootstrap gProjectileLuaFunctionThunksBootstrap;
} // namespace
