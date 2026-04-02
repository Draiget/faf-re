#pragma once

struct lua_State;

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class CScrLuaInitForm;

  /**
   * Address: 0x004B41E0 (FUN_004B41E0, cfunc_Trace)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_TraceL`.
   */
  int cfunc_Trace(lua_State* luaContext);

  /**
   * Address: 0x004B4260 (FUN_004B4260, cfunc_TraceL)
   *
   * What it does:
   * Validates one boolean argument for the `Trace` Lua API and returns no
   * Lua values.
   */
  int cfunc_TraceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004B4200 (FUN_004B4200, func_Trace_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `Trace`.
   */
  CScrLuaInitForm* func_Trace_LuaFuncDef();

  /**
   * Address: 0x00BC5D50 (FUN_00BC5D50, register_Trace_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_Trace_LuaFuncDef`.
   */
  CScrLuaInitForm* register_Trace_LuaFuncDef();
} // namespace moho

