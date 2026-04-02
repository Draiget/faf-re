#include "moho/lua/CScrLuaInitForm.h"

namespace
{
  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardUnitWeaponLuaThunk() noexcept
  {
    return Target();
  }
} // namespace

namespace moho
{
  // Underlying Lua function-definition publishers referenced by this thunk pack.
  CScrLuaInitForm* func_UnitWeaponPlaySound_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponSetEnabled_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponSetTargetEntity_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponSetTargetGround_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponResetTarget_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponCreateProjectile_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponDoInstaHit_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponGetBlueprint_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponGetProjectileBlueprint_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponHasTarget_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponFireWeapon_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponSetFireControl_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponIsFireControl_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponGetCurrentTarget_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponGetCurrentTargetPos_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponCanFire_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponChangeFiringTolerance_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponChangeRateOfFire_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponChangeMinRadius_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponChangeMaxRadius_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponChangeMaxHeightDiff_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponChangeDamageType_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponChangeDamageRadius_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponChangeDamage_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponSetFireTargetLayerCaps_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponSetTargetingPriorities_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponGetFiringRandomness_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponSetFiringRandomness_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponGetFireClockPct_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponChangeProjectileBlueprint_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponTransferTarget_LuaFuncDef();
  CScrLuaInitForm* func_UnitWeaponBeenDestroyed_LuaFuncDef();

  /**
   * Address: 0x00BD8970 (FUN_00BD8970, j_func_UnitWeaponPlaySound_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponPlaySound_LuaFuncDef` to `func_UnitWeaponPlaySound_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponPlaySound_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponPlaySound_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8980 (FUN_00BD8980, j_func_UnitWeaponSetEnabled_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponSetEnabled_LuaFuncDef` to `func_UnitWeaponSetEnabled_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponSetEnabled_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponSetEnabled_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8990 (FUN_00BD8990, register_UnitWeaponSetTargetEntity_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponSetTargetEntity_LuaFuncDef` to `func_UnitWeaponSetTargetEntity_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponSetTargetEntity_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponSetTargetEntity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD89A0 (FUN_00BD89A0, j_func_UnitWeaponSetTargetGround_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponSetTargetGround_LuaFuncDef` to `func_UnitWeaponSetTargetGround_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponSetTargetGround_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponSetTargetGround_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD89B0 (FUN_00BD89B0, register_UnitWeaponResetTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponResetTarget_LuaFuncDef` to `func_UnitWeaponResetTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponResetTarget_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponResetTarget_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD89C0 (FUN_00BD89C0, register_UnitWeaponCreateProjectile_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponCreateProjectile_LuaFuncDef` to `func_UnitWeaponCreateProjectile_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponCreateProjectile_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponCreateProjectile_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD89D0 (FUN_00BD89D0, j_func_UnitWeaponDoInstaHit_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponDoInstaHit_LuaFuncDef` to `func_UnitWeaponDoInstaHit_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponDoInstaHit_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponDoInstaHit_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD89E0 (FUN_00BD89E0, register_UnitWeaponGetBlueprint_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponGetBlueprint_LuaFuncDef` to `func_UnitWeaponGetBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponGetBlueprint_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponGetBlueprint_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD89F0 (FUN_00BD89F0, register_UnitWeaponGetProjectileBlueprint_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponGetProjectileBlueprint_LuaFuncDef` to `func_UnitWeaponGetProjectileBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponGetProjectileBlueprint_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponGetProjectileBlueprint_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8A00 (FUN_00BD8A00, register_UnitWeaponHasTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponHasTarget_LuaFuncDef` to `func_UnitWeaponHasTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponHasTarget_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponHasTarget_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8A10 (FUN_00BD8A10, register_UnitWeaponFireWeapon_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponFireWeapon_LuaFuncDef` to `func_UnitWeaponFireWeapon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponFireWeapon_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponFireWeapon_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8A20 (FUN_00BD8A20, register_UnitWeaponSetFireControl_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponSetFireControl_LuaFuncDef` to `func_UnitWeaponSetFireControl_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponSetFireControl_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponSetFireControl_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8A30 (FUN_00BD8A30, j_func_UnitWeaponIsFireControl_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponIsFireControl_LuaFuncDef` to `func_UnitWeaponIsFireControl_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponIsFireControl_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponIsFireControl_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8A40 (FUN_00BD8A40, register_UnitWeaponGetCurrentTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponGetCurrentTarget_LuaFuncDef` to `func_UnitWeaponGetCurrentTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponGetCurrentTarget_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponGetCurrentTarget_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8A50 (FUN_00BD8A50, register_UnitWeaponGetCurrentTargetPos_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponGetCurrentTargetPos_LuaFuncDef` to `func_UnitWeaponGetCurrentTargetPos_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponGetCurrentTargetPos_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponGetCurrentTargetPos_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8A60 (FUN_00BD8A60, j_func_UnitWeaponCanFire_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponCanFire_LuaFuncDef` to `func_UnitWeaponCanFire_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponCanFire_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponCanFire_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8A70 (FUN_00BD8A70, register_UnitWeaponChangeFiringTolerance_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponChangeFiringTolerance_LuaFuncDef` to `func_UnitWeaponChangeFiringTolerance_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponChangeFiringTolerance_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponChangeFiringTolerance_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8A80 (FUN_00BD8A80, register_UnitWeaponChangeRateOfFire_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponChangeRateOfFire_LuaFuncDef` to `func_UnitWeaponChangeRateOfFire_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponChangeRateOfFire_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponChangeRateOfFire_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8A90 (FUN_00BD8A90, j_func_UnitWeaponChangeMinRadius_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponChangeMinRadius_LuaFuncDef` to `func_UnitWeaponChangeMinRadius_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponChangeMinRadius_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponChangeMinRadius_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8AA0 (FUN_00BD8AA0, register_UnitWeaponChangeMaxRadius_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponChangeMaxRadius_LuaFuncDef` to `func_UnitWeaponChangeMaxRadius_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponChangeMaxRadius_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponChangeMaxRadius_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8AB0 (FUN_00BD8AB0, register_UnitWeaponChangeMaxHeightDiff_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponChangeMaxHeightDiff_LuaFuncDef` to `func_UnitWeaponChangeMaxHeightDiff_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponChangeMaxHeightDiff_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponChangeMaxHeightDiff_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8AC0 (FUN_00BD8AC0, j_func_UnitWeaponChangeDamageType_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponChangeDamageType_LuaFuncDef` to `func_UnitWeaponChangeDamageType_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponChangeDamageType_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponChangeDamageType_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8AD0 (FUN_00BD8AD0, register_UnitWeaponChangeDamageRadius_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponChangeDamageRadius_LuaFuncDef` to `func_UnitWeaponChangeDamageRadius_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponChangeDamageRadius_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponChangeDamageRadius_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8AE0 (FUN_00BD8AE0, register_UnitWeaponChangeDamage_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponChangeDamage_LuaFuncDef` to `func_UnitWeaponChangeDamage_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponChangeDamage_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponChangeDamage_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8AF0 (FUN_00BD8AF0, j_func_UnitWeaponSetFireTargetLayerCaps_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponSetFireTargetLayerCaps_LuaFuncDef` to `func_UnitWeaponSetFireTargetLayerCaps_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponSetFireTargetLayerCaps_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponSetFireTargetLayerCaps_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8B00 (FUN_00BD8B00, register_UnitWeaponSetTargetingPriorities_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponSetTargetingPriorities_LuaFuncDef` to `func_UnitWeaponSetTargetingPriorities_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponSetTargetingPriorities_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponSetTargetingPriorities_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8B10 (FUN_00BD8B10, register_UnitWeaponGetFiringRandomness_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponGetFiringRandomness_LuaFuncDef` to `func_UnitWeaponGetFiringRandomness_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponGetFiringRandomness_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponGetFiringRandomness_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8B20 (FUN_00BD8B20, j_func_UnitWeaponSetFiringRandomness_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponSetFiringRandomness_LuaFuncDef` to `func_UnitWeaponSetFiringRandomness_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponSetFiringRandomness_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponSetFiringRandomness_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8B30 (FUN_00BD8B30, register_UnitWeaponGetFireClockPct_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponGetFireClockPct_LuaFuncDef` to `func_UnitWeaponGetFireClockPct_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponGetFireClockPct_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponGetFireClockPct_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8B40 (FUN_00BD8B40, register_UnitWeaponChangeProjectileBlueprint_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponChangeProjectileBlueprint_LuaFuncDef` to `func_UnitWeaponChangeProjectileBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponChangeProjectileBlueprint_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponChangeProjectileBlueprint_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8B50 (FUN_00BD8B50, register_UnitWeaponTransferTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponTransferTarget_LuaFuncDef` to `func_UnitWeaponTransferTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponTransferTarget_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponTransferTarget_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD8B60 (FUN_00BD8B60, register_UnitWeaponBeenDestroyed_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_UnitWeaponBeenDestroyed_LuaFuncDef` to `func_UnitWeaponBeenDestroyed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitWeaponBeenDestroyed_LuaFuncDef()
  {
    return ForwardUnitWeaponLuaThunk<&func_UnitWeaponBeenDestroyed_LuaFuncDef>();
  }
} // namespace moho
