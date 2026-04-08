#pragma once

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
}

struct lua_State;

namespace moho
{
  class CScrLuaInitForm;

  /**
   * Address: 0x0073A810 (FUN_0073A810, func_CreateLuaCDamage)
   *
   * What it does:
   * Resolves one cached Lua metatable object for CDamage userdata creation.
   */
  LuaPlus::LuaObject* func_CreateLuaCDamage(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00738BD0 (FUN_00738BD0, cfunc_Damage)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_DamageL`.
   */
  int cfunc_Damage(lua_State* luaContext);

  /**
   * Address: 0x00738C50 (FUN_00738C50, cfunc_DamageL)
   *
   * What it does:
   * Builds one transient `CDamage` payload from Lua args and dispatches it
   * through `SIM_Damage`.
   */
  int cfunc_DamageL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00738BF0 (FUN_00738BF0, func_Damage_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `Damage`.
   */
  CScrLuaInitForm* func_Damage_LuaFuncDef();

  /**
   * Address: 0x00BDB790 (FUN_00BDB790, register_Damage_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_Damage_LuaFuncDef`.
   */
  CScrLuaInitForm* register_Damage_LuaFuncDef();

  /**
   * Address: 0x00738F40 (FUN_00738F40, cfunc_DamageArea)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_DamageAreaL`.
   */
  int cfunc_DamageArea(lua_State* luaContext);

  /**
   * Address: 0x00738FC0 (FUN_00738FC0, cfunc_DamageAreaL)
   *
   * What it does:
   * Builds one area-effect `CDamage` payload and dispatches it through
   * `SIM_Damage`.
   */
  int cfunc_DamageAreaL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00738F60 (FUN_00738F60, func_DamageArea_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `DamageArea`.
   */
  CScrLuaInitForm* func_DamageArea_LuaFuncDef();

  /**
   * Address: 0x00BDB7A0 (FUN_00BDB7A0, register_DamageArea_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_DamageArea_LuaFuncDef`.
   */
  CScrLuaInitForm* register_DamageArea_LuaFuncDef();

  /**
   * Address: 0x007392C0 (FUN_007392C0, cfunc_DamageRing)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_DamageRingL`.
   */
  int cfunc_DamageRing(lua_State* luaContext);

  /**
   * Address: 0x00739340 (FUN_00739340, cfunc_DamageRingL)
   *
   * What it does:
   * Builds one ring-effect `CDamage` payload and dispatches it through
   * `SIM_Damage`.
   */
  int cfunc_DamageRingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007392E0 (FUN_007392E0, func_DamageRing_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `DamageRing`.
   */
  CScrLuaInitForm* func_DamageRing_LuaFuncDef();

  /**
   * Address: 0x00BDB7B0 (FUN_00BDB7B0, register_DamageRing_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_DamageRing_LuaFuncDef`.
   */
  CScrLuaInitForm* register_DamageRing_LuaFuncDef();

  /**
   * Address: 0x00738630 (FUN_00738630, cfunc_CDamageGetInstigator)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CDamageGetInstigatorL`.
   */
  int cfunc_CDamageGetInstigator(lua_State* luaContext);

  /**
   * Address: 0x007386B0 (FUN_007386B0, cfunc_CDamageGetInstigatorL)
   *
   * What it does:
   * Resolves one `CDamage` object and returns its live instigator entity Lua object,
   * or `nil` when the weak reference is null/dead.
   */
  int cfunc_CDamageGetInstigatorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00738650 (FUN_00738650, func_CDamageGetInstigator_LuaFuncDef)
   *
   * What it does:
   * Publishes `CDamage:GetInstigator()` in the sim Lua init-form set.
   */
  CScrLuaInitForm* func_CDamageGetInstigator_LuaFuncDef();

  /**
   * Address: 0x00738790 (FUN_00738790, cfunc_CDamageSetInstigator)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CDamageSetInstigatorL`.
   */
  int cfunc_CDamageSetInstigator(lua_State* luaContext);

  /**
   * Address: 0x00738810 (FUN_00738810, cfunc_CDamageSetInstigatorL)
   *
   * What it does:
   * Resolves `CDamage` + `Entity` arguments and stores the instigator weak link.
   */
  int cfunc_CDamageSetInstigatorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007387B0 (FUN_007387B0, func_CDamageSetInstigator_LuaFuncDef)
   *
   * What it does:
   * Publishes `CDamage:SetInstigator()` in the sim Lua init-form set.
   */
  CScrLuaInitForm* func_CDamageSetInstigator_LuaFuncDef();

  /**
   * Address: 0x00738900 (FUN_00738900, cfunc_CDamageGetTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CDamageGetTargetL`.
   */
  int cfunc_CDamageGetTarget(lua_State* luaContext);

  /**
   * Address: 0x00738980 (FUN_00738980, cfunc_CDamageGetTargetL)
   *
   * What it does:
   * Resolves one `CDamage` object and returns its live target entity Lua object,
   * or `nil` when the weak reference is null/dead.
   */
  int cfunc_CDamageGetTargetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00738920 (FUN_00738920, func_CDamageGetTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `CDamage:GetTarget()` in the sim Lua init-form set.
   */
  CScrLuaInitForm* func_CDamageGetTarget_LuaFuncDef();

  /**
   * Address: 0x00738A60 (FUN_00738A60, cfunc_CDamageSetTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CDamageSetTargetL`.
   */
  int cfunc_CDamageSetTarget(lua_State* luaContext);

  /**
   * Address: 0x00738AE0 (FUN_00738AE0, cfunc_CDamageSetTargetL)
   *
   * What it does:
   * Resolves `CDamage` + `Entity` arguments and stores the target weak link.
   */
  int cfunc_CDamageSetTargetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00738A80 (FUN_00738A80, func_CDamageSetTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `CDamage:SetTarget()` in the sim Lua init-form set.
   */
  CScrLuaInitForm* func_CDamageSetTarget_LuaFuncDef();
} // namespace moho
