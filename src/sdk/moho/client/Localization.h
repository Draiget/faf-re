#pragma once

#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  /**
   * Address: 0x004797B0 (FUN_004797B0)
   * Mangled:
   * ?Loc@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PAVLuaState@LuaPlus@@VStrArg@gpg@@@Z
   *
   * LuaPlus::LuaState *, gpg::StrArg
   *
   * What it does:
   * Calls global Lua `LOC(key)` and returns the localized string.
   * If Lua call/type handling throws, logs warning and falls back to `key`.
   */
  msvc8::string Loc(LuaPlus::LuaState* state, gpg::StrArg key);
} // namespace moho
