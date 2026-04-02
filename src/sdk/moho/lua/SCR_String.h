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
   * Address: 0x004D3810 (FUN_004D3810, cfunc_STR_Utf8SubString)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_STR_Utf8SubStringL`.
   */
  int cfunc_STR_Utf8SubString(lua_State* luaContext);

  /**
   * Address: 0x004D3890 (FUN_004D3890, cfunc_STR_Utf8SubStringL)
   *
   * What it does:
   * Validates `(string, start, count)` Lua args, returns the UTF-8 substring
   * at one-based `start` for `count` codepoints.
   */
  int cfunc_STR_Utf8SubStringL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D3830 (FUN_004D3830, func_STR_Utf8SubString_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `STR_Utf8SubString`.
   */
  CScrLuaInitForm* func_STR_Utf8SubString_LuaFuncDef();

  /**
   * Address: 0x00BC65F0 (FUN_00BC65F0, register_STR_Utf8SubString_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_STR_Utf8SubString_LuaFuncDef`.
   */
  CScrLuaInitForm* register_STR_Utf8SubString_LuaFuncDef();
} // namespace moho

