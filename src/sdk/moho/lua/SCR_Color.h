#pragma once

#include <cstdint>

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
   * Address: 0x004B2D20 (FUN_004B2D20, Moho::SCR_DecodeColor)
   *
   * What it does:
   * Decodes one Lua string color token into packed ARGB, reporting Lua errors
   * on type mismatch or unknown names.
   */
  [[nodiscard]] std::uint32_t SCR_DecodeColor(LuaPlus::LuaState* state, const LuaPlus::LuaObject& colorObject);

  /**
   * Address: 0x004B2D80 (FUN_004B2D80, Moho::SCR_DecodeColor)
   *
   * What it does:
   * Decodes one color string into packed ARGB and throws `XDataError` on
   * unknown color names/hex payloads.
   */
  [[nodiscard]] std::uint32_t SCR_DecodeColor(const msvc8::string& colorText);

  /**
   * Address: 0x004B2E60 (FUN_004B2E60, Moho::SCR_EncodeColor)
   *
   * What it does:
   * Encodes one packed ARGB value as lowercase 8-digit hex Lua string object.
   */
  [[nodiscard]] LuaPlus::LuaObject SCR_EncodeColor(LuaPlus::LuaState* state, std::uint32_t colorValue);

  /**
   * Address: 0x004B2EE0 (FUN_004B2EE0, cfunc_EnumColorNames)
   *
   * What it does:
   * Unwraps raw Lua callback state and forwards to `cfunc_EnumColorNamesL`.
   */
  int cfunc_EnumColorNames(lua_State* luaContext);

  /**
   * Address: 0x004B2F60 (FUN_004B2F60, cfunc_EnumColorNamesL)
   *
   * What it does:
   * Returns a Lua table listing every registered named color.
   */
  int cfunc_EnumColorNamesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004B2F00 (FUN_004B2F00, func_EnumColorNames_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EnumColorNames`.
   */
  CScrLuaInitForm* func_EnumColorNames_LuaFuncDef();
} // namespace moho

