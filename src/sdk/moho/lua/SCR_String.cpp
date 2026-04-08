#include "moho/lua/SCR_String.h"

#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/misc/FileWaitHandleSet.h"

namespace
{
  constexpr const char* kXtoiHelpText = "int STR_xtoi(string) - converts a hexidecimal string to an integer";
  constexpr const char* kItoxHelpText = "string STR_itox(int) - converts an integer into a hexidecimal string";
  constexpr const char* kUtf8LenHelpText = "int STR_Utf8Len(string) - return the number of characters in a UTF-8 string";
  constexpr const char* kUtf8SubStringHelpText =
    "string STR_Utf8SubString(string, start, count) - return a substring from start to count";
  constexpr const char* kGetTokensHelpText = "table STR_GetTokens(string,delimiter)";
  constexpr const char* kExistsHelpText = "exists(name) -> bool -- returns true if the given resource file exists";
  constexpr const char* kGetVersionHelpText = "GetVersion() -> string";

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
 * Address: 0x004D3470 (FUN_004D3470, cfunc_STR_xtoi)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_STR_xtoiL`.
 */
int moho::cfunc_STR_xtoi(lua_State* const luaContext)
{
  return cfunc_STR_xtoiL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D34F0 (FUN_004D34F0, cfunc_STR_xtoiL)
 *
 * What it does:
 * Converts one hexadecimal string argument to a numeric value.
 */
int moho::cfunc_STR_xtoiL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kXtoiHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject sourceArgument(state, 1);
  const char* const sourceText = lua_tostring(state->m_state, 1);
  if (sourceText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&sourceArgument, "string");
  }

  lua_pushnumber(state->m_state, static_cast<float>(gpg::STR_Xtoi(sourceText)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D3490 (FUN_004D3490, func_STR_xtoi_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `STR_xtoi`.
 */
moho::CScrLuaInitForm* moho::func_STR_xtoi_LuaFuncDef()
{
  static CScrLuaBinder binder(CoreLuaInitSet(), "STR_xtoi", &moho::cfunc_STR_xtoi, nullptr, "<global>", kXtoiHelpText);
  return &binder;
}

/**
 * Address: 0x00BC65C0 (FUN_00BC65C0, register_STR_xtoi_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_STR_xtoi_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_STR_xtoi_LuaFuncDef()
{
  return func_STR_xtoi_LuaFuncDef();
}

/**
 * Address: 0x004D3580 (FUN_004D3580, cfunc_STR_itox)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_STR_itoxL`.
 */
int moho::cfunc_STR_itox(lua_State* const luaContext)
{
  return cfunc_STR_itoxL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D3600 (FUN_004D3600, cfunc_STR_itoxL)
 *
 * What it does:
 * Validates one integer-like Lua arg and pushes its uppercase hexadecimal
 * string representation.
 */
int moho::cfunc_STR_itoxL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kItoxHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject valueArgument(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&valueArgument, "integer");
  }

  const double numericValue = lua_tonumber(state->m_state, 1);
  const msvc8::string hexText = gpg::STR_Printf("%X", static_cast<int>(numericValue));
  lua_pushstring(state->m_state, hexText.c_str());
  return 1;
}

/**
 * Address: 0x004D35A0 (FUN_004D35A0, func_STR_itox_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `STR_itox`.
 */
moho::CScrLuaInitForm* moho::func_STR_itox_LuaFuncDef()
{
  static CScrLuaBinder binder(CoreLuaInitSet(), "STR_itox", &moho::cfunc_STR_itox, nullptr, "<global>", kItoxHelpText);
  return &binder;
}

/**
 * Address: 0x00BC65D0 (FUN_00BC65D0, register_STR_itox_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_STR_itox_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_STR_itox_LuaFuncDef()
{
  return func_STR_itox_LuaFuncDef();
}

/**
 * Address: 0x004D3700 (FUN_004D3700, cfunc_STR_Utf8Len)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_STR_Utf8LenL`.
 */
int moho::cfunc_STR_Utf8Len(lua_State* const luaContext)
{
  return cfunc_STR_Utf8LenL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D3780 (FUN_004D3780, cfunc_STR_Utf8LenL)
 *
 * What it does:
 * Returns UTF-8 codepoint count for one input string.
 */
int moho::cfunc_STR_Utf8LenL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kUtf8LenHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject sourceArgument(state, 1);
  const char* const sourceText = lua_tostring(state->m_state, 1);
  if (sourceText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&sourceArgument, "string");
  }

  lua_pushnumber(state->m_state, static_cast<float>(gpg::STR_Utf8Len(sourceText)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D3720 (FUN_004D3720, func_STR_Utf8Len_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `STR_Utf8Len`.
 */
moho::CScrLuaInitForm* moho::func_STR_Utf8Len_LuaFuncDef()
{
  static CScrLuaBinder
    binder(CoreLuaInitSet(), "STR_Utf8Len", &moho::cfunc_STR_Utf8Len, nullptr, "<global>", kUtf8LenHelpText);
  return &binder;
}

/**
 * Address: 0x00BC65E0 (FUN_00BC65E0, register_STR_Utf8Len_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_STR_Utf8Len_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_STR_Utf8Len_LuaFuncDef()
{
  return func_STR_Utf8Len_LuaFuncDef();
}

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

/**
 * Address: 0x004D3A10 (FUN_004D3A10, cfunc_STR_GetTokens)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_STR_GetTokensL`.
 */
int moho::cfunc_STR_GetTokens(lua_State* const luaContext)
{
  return cfunc_STR_GetTokensL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D3A90 (FUN_004D3A90, cfunc_STR_GetTokensL)
 *
 * What it does:
 * Splits one input string by delimiter and returns a Lua table of tokens.
 */
int moho::cfunc_STR_GetTokensL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetTokensHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject sourceArgument(state, 1);
  const char* const sourceText = lua_tostring(state->m_state, 1);
  if (sourceText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&sourceArgument, "string");
  }

  LuaPlus::LuaStackObject delimiterArgument(state, 2);
  const char* const delimiterText = lua_tostring(state->m_state, 2);
  if (delimiterText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&delimiterArgument, "string");
  }

  msvc8::vector<msvc8::string> tokens{};
  gpg::STR_GetTokens(sourceText, delimiterText, tokens);

  LuaPlus::LuaObject tokenTable;
  tokenTable.AssignNewTable(state, static_cast<int>(tokens.size()), 0);

  int tokenIndex = 0;
  for (const msvc8::string& token : tokens) {
    tokenTable.SetString(tokenIndex++, token.c_str());
  }

  tokenTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x004D3A30 (FUN_004D3A30, func_STR_GetTokens_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `STR_GetTokens`.
 */
moho::CScrLuaInitForm* moho::func_STR_GetTokens_LuaFuncDef()
{
  static CScrLuaBinder
    binder(CoreLuaInitSet(), "STR_GetTokens", &moho::cfunc_STR_GetTokens, nullptr, "<global>", kGetTokensHelpText);
  return &binder;
}

/**
 * Address: 0x00BC6600 (FUN_00BC6600, register_STR_GetTokens_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_STR_GetTokens_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_STR_GetTokens_LuaFuncDef()
{
  return func_STR_GetTokens_LuaFuncDef();
}

/**
 * Address: 0x004D3D30 (FUN_004D3D30, Moho::GetEngineVersion)
 *
 * What it does:
 * Builds the fixed engine version string used by Lua and console callbacks.
 */
msvc8::string moho::GetEngineVersion()
{
  return gpg::STR_Printf("%1.1f.%i", 1.5, 3764);
}

/**
 * Address: 0x004D3D70 (FUN_004D3D70, cfunc_exists)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_existsL`.
 */
int moho::cfunc_exists(lua_State* const luaContext)
{
  return cfunc_existsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D3DF0 (FUN_004D3DF0, cfunc_existsL)
 *
 * What it does:
 * Returns Lua boolean indicating whether a resource path exists.
 */
int moho::cfunc_existsL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kExistsHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject sourceArgument(state, 1);
  const char* const sourcePath = lua_tostring(state->m_state, 1);
  if (sourcePath == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&sourceArgument, "string");
  }

  const moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
  const bool exists = waitHandleSet != nullptr && waitHandleSet->mHandle != nullptr
    && waitHandleSet->mHandle->GetFileInfo(sourcePath, nullptr);
  lua_pushboolean(state->m_state, exists ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D3D90 (FUN_004D3D90, func_exists_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `exists`.
 */
moho::CScrLuaInitForm* moho::func_exists_LuaFuncDef()
{
  static CScrLuaBinder binder(CoreLuaInitSet(), "exists", &moho::cfunc_exists, nullptr, "<global>", kExistsHelpText);
  return &binder;
}

/**
 * Address: 0x00BC6610 (FUN_00BC6610, register_exists_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_exists_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_exists_LuaFuncDef()
{
  return func_exists_LuaFuncDef();
}

/**
 * Address: 0x004D3EA0 (FUN_004D3EA0, cfunc_GetVersion)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetVersionL`.
 */
int moho::cfunc_GetVersion(lua_State* const luaContext)
{
  return cfunc_GetVersionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D3F20 (FUN_004D3F20, cfunc_GetVersionL)
 *
 * What it does:
 * Pushes one engine-version string and returns it.
 */
int moho::cfunc_GetVersionL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetVersionHelpText, 0, argumentCount);
  }

  const msvc8::string engineVersion = GetEngineVersion();
  lua_pushstring(state->m_state, engineVersion.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D3EC0 (FUN_004D3EC0, func_GetVersion_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetVersion`.
 */
moho::CScrLuaInitForm* moho::func_GetVersion_LuaFuncDef()
{
  static CScrLuaBinder
    binder(CoreLuaInitSet(), "GetVersion", &moho::cfunc_GetVersion, nullptr, "<global>", kGetVersionHelpText);
  return &binder;
}

/**
 * Address: 0x00BC6620 (FUN_00BC6620, register_GetVersion_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_GetVersion_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_GetVersion_LuaFuncDef()
{
  return func_GetVersion_LuaFuncDef();
}
