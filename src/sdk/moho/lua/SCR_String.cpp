#include "moho/lua/SCR_String.h"

#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"

namespace
{
  constexpr const char* kUtf8SubStringHelpText =
    "string STR_Utf8SubString(string, start, count) - return a substring from start to count";

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }
} // namespace

/**
 * Address: 0x004D3810 (FUN_004D3810, cfunc_STR_Utf8SubString)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_STR_Utf8SubStringL`.
 */
int moho::cfunc_STR_Utf8SubString(lua_State* const luaContext)
{
  return cfunc_STR_Utf8SubStringL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D3890 (FUN_004D3890, cfunc_STR_Utf8SubStringL)
 *
 * What it does:
 * Validates `(string, start, count)` Lua args, returns the UTF-8 substring
 * at one-based `start` for `count` codepoints.
 */
int moho::cfunc_STR_Utf8SubStringL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kUtf8SubStringHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaStackObject countArgument(state, 3);
  const int count = countArgument.GetInteger();

  const LuaPlus::LuaStackObject startArgument(state, 2);
  const int start = startArgument.GetInteger();

  const LuaPlus::LuaStackObject sourceArgument(state, 1);
  const char* const sourceText = sourceArgument.GetString();

  const msvc8::string substring = gpg::STR_Utf8SubString(sourceText, start - 1, count);
  lua_pushstring(state->m_state, substring.c_str());
  return 1;
}

/**
 * Address: 0x004D3830 (FUN_004D3830, func_STR_Utf8SubString_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `STR_Utf8SubString`.
 */
moho::CScrLuaInitForm* moho::func_STR_Utf8SubString_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "STR_Utf8SubString",
    &moho::cfunc_STR_Utf8SubString,
    nullptr,
    "<global>",
    kUtf8SubStringHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC65F0 (FUN_00BC65F0, register_STR_Utf8SubString_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_STR_Utf8SubString_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_STR_Utf8SubString_LuaFuncDef()
{
  return func_STR_Utf8SubString_LuaFuncDef();
}

