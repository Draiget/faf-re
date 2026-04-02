// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "moho/lua/CScrLuaBinderFwd.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus
struct lua_State;

namespace moho
{
  /**
   * Address: 0x00BCEC90 (FUN_00BCEC90, register_AITarget_LuaFuncDef)
   *
   * What it does:
   * Forwards startup registration to `func_AITarget_LuaFuncDef`.
   */
  void register_AITarget_LuaFuncDef();

  /**
   * Address: 0x005E3150 (FUN_005E3150, cfunc_AITarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_AITargetL`.
   */
  int cfunc_AITarget(lua_State* luaContext);

  /**
   * Address: 0x005E31D0 (FUN_005E31D0, cfunc_AITargetL)
   *
   * What it does:
   * Builds one `CAiTarget` from optional Lua arg#1 (`Entity` object or
   * position table) and returns the Lua target object payload.
   */
  int cfunc_AITargetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005E3170 (FUN_005E3170, func_AITarget_LuaFuncDef)
   *
   * What it does:
   * Initializes the `AITarget` Lua binder record and links it into the global
   * script init list.
   */
  void func_AITarget_LuaFuncDef();

  /**
   * VFTABLE: 0x00E1ED64
   * COL:  0x00E761BC
   */
  using AITarget_LuaFuncDef = ::moho::CScrLuaBinder;
} // namespace moho
