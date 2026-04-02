#include "Localization.h"

#include <cstring>
#include <exception>
#include <stdexcept>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
using namespace moho;

namespace
{
  [[nodiscard]] bool IsLuaCallableFunction(const LuaPlus::LuaObject& object) noexcept
  {
    // Recovered from LuaObject::IsFunction: (tt | 1) == LUA_TFUNCTION.
    return object.m_state != nullptr && ((object.m_object.tt | 1) == LUA_TFUNCTION);
  }
} // namespace

/**
 * Address: 0x004797B0 (FUN_004797B0)
 * Mangled:
 * ?Loc@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PAVLuaState@LuaPlus@@VStrArg@gpg@@@Z
 *
 * LuaPlus::LuaState *, gpg::StrArg
 *
 * What it does:
 * Calls Lua global `LOC` with `key` and returns copied string result.
 * On exception, logs warning and returns the original `key`.
 */
msvc8::string moho::Loc(LuaPlus::LuaState* const state, const gpg::StrArg key)
{
  const char* const input = key ? key : "";

  try {
    LuaPlus::LuaObject locObject = state->GetGlobal("LOC");
    if (!IsLuaCallableFunction(locObject)) {
      throw std::runtime_error("attempt to call a non-function value");
    }

    if (locObject.GetActiveCState() == nullptr) {
      throw std::runtime_error("LOC has no active lua_State");
    }

    LuaPlus::LuaFunction<const char*> locFunction(locObject);
    const char* const localized = locFunction(input);
    const char* const out = localized ? localized : "";
    const msvc8::string result(out, std::strlen(out));
    return result;
  } catch (const std::exception& ex) {
    gpg::Warnf("Error localizing \"%s\": %s", input, ex.what() ? ex.what() : "<unknown>");
  } catch (...) {
    gpg::Warnf("Error localizing \"%s\": %s", input, "<unknown>");
  }

  return msvc8::string(input);
}
