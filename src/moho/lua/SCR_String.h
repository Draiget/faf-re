#pragma once

#include "legacy/containers/String.h"

struct lua_State;

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
}

namespace moho
{
  class CScrLuaInitForm;

  /**
   * Address: 0x004D3110 (FUN_004D3110, ?SCR_FromString@Moho@@YA?AVLuaObject@LuaPlus@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PAVLuaState@3@@Z)
   *
   * What it does:
   * Wraps a contiguous std::string payload in an in-memory MemBufferStream and
   * deserializes one tagged Lua value out of it through SCR_FromByteStream.
   * Returns the populated LuaObject by output parameter (RVO slot).
   */
  LuaPlus::LuaObject* SCR_FromString(
      LuaPlus::LuaObject* outObject, const msvc8::string& source, LuaPlus::LuaState* state);

  /**
   * Address: 0x004D3D30 (FUN_004D3D30, Moho::GetEngineVersion)
   *
   * What it does:
   * Builds the fixed engine version string used by Lua and console callbacks.
   */
  [[nodiscard]] msvc8::string GetEngineVersion();

  /**
   * Address: 0x004D3470 (FUN_004D3470, cfunc_STR_xtoi)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_STR_xtoiL`.
   */
  int cfunc_STR_xtoi(lua_State* luaContext);

  /**
   * Address: 0x004D34F0 (FUN_004D34F0, cfunc_STR_xtoiL)
   *
   * What it does:
   * Converts one hexadecimal string argument to a numeric value.
   */
  int cfunc_STR_xtoiL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D3490 (FUN_004D3490, func_STR_xtoi_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `STR_xtoi`.
   */
  CScrLuaInitForm* func_STR_xtoi_LuaFuncDef();

  /**
   * Address: 0x00BC65C0 (FUN_00BC65C0, register_STR_xtoi_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_STR_xtoi_LuaFuncDef`.
   */
  CScrLuaInitForm* register_STR_xtoi_LuaFuncDef();

  /**
   * Address: 0x004D3580 (FUN_004D3580, cfunc_STR_itox)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_STR_itoxL`.
   */
  int cfunc_STR_itox(lua_State* luaContext);

  /**
   * Address: 0x004D3600 (FUN_004D3600, cfunc_STR_itoxL)
   *
   * What it does:
   * Validates one integer-like Lua arg and pushes its uppercase hexadecimal
   * string representation.
   */
  int cfunc_STR_itoxL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D35A0 (FUN_004D35A0, func_STR_itox_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `STR_itox`.
   */
  CScrLuaInitForm* func_STR_itox_LuaFuncDef();

  /**
   * Address: 0x00BC65D0 (FUN_00BC65D0, register_STR_itox_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_STR_itox_LuaFuncDef`.
   */
  CScrLuaInitForm* register_STR_itox_LuaFuncDef();

  /**
   * Address: 0x004D3700 (FUN_004D3700, cfunc_STR_Utf8Len)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_STR_Utf8LenL`.
   */
  int cfunc_STR_Utf8Len(lua_State* luaContext);

  /**
   * Address: 0x004D3780 (FUN_004D3780, cfunc_STR_Utf8LenL)
   *
   * What it does:
   * Returns UTF-8 codepoint count for one input string.
   */
  int cfunc_STR_Utf8LenL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D3720 (FUN_004D3720, func_STR_Utf8Len_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `STR_Utf8Len`.
   */
  CScrLuaInitForm* func_STR_Utf8Len_LuaFuncDef();

  /**
   * Address: 0x00BC65E0 (FUN_00BC65E0, register_STR_Utf8Len_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_STR_Utf8Len_LuaFuncDef`.
   */
  CScrLuaInitForm* register_STR_Utf8Len_LuaFuncDef();

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

  /**
   * Address: 0x004D3A10 (FUN_004D3A10, cfunc_STR_GetTokens)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_STR_GetTokensL`.
   */
  int cfunc_STR_GetTokens(lua_State* luaContext);

  /**
   * Address: 0x004D3A90 (FUN_004D3A90, cfunc_STR_GetTokensL)
   *
   * What it does:
   * Splits one input string by delimiter and returns a Lua table of tokens.
   */
  int cfunc_STR_GetTokensL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D3A30 (FUN_004D3A30, func_STR_GetTokens_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `STR_GetTokens`.
   */
  CScrLuaInitForm* func_STR_GetTokens_LuaFuncDef();

  /**
   * Address: 0x00BC6600 (FUN_00BC6600, register_STR_GetTokens_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_STR_GetTokens_LuaFuncDef`.
   */
  CScrLuaInitForm* register_STR_GetTokens_LuaFuncDef();

  /**
   * Address: 0x004D3D70 (FUN_004D3D70, cfunc_exists)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_existsL`.
   */
  int cfunc_exists(lua_State* luaContext);

  /**
   * Address: 0x004D3DF0 (FUN_004D3DF0, cfunc_existsL)
   *
   * What it does:
   * Returns Lua boolean indicating whether a resource path exists.
   */
  int cfunc_existsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D3D90 (FUN_004D3D90, func_exists_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `exists`.
   */
  CScrLuaInitForm* func_exists_LuaFuncDef();

  /**
   * Address: 0x00BC6610 (FUN_00BC6610, register_exists_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_exists_LuaFuncDef`.
   */
  CScrLuaInitForm* register_exists_LuaFuncDef();

  /**
   * Address: 0x004D3EA0 (FUN_004D3EA0, cfunc_GetVersion)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetVersionL`.
   */
  int cfunc_GetVersion(lua_State* luaContext);

  /**
   * Address: 0x004D3F20 (FUN_004D3F20, cfunc_GetVersionL)
   *
   * What it does:
   * Pushes one engine-version string and returns it.
   */
  int cfunc_GetVersionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D3EC0 (FUN_004D3EC0, func_GetVersion_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetVersion`.
   */
  CScrLuaInitForm* func_GetVersion_LuaFuncDef();

  /**
   * Address: 0x00BC6620 (FUN_00BC6620, register_GetVersion_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_GetVersion_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetVersion_LuaFuncDef();
} // namespace moho
