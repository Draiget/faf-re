#pragma once

#include <cstddef>
#include <initializer_list>
#include <string>
#include <string_view>

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
  fa::string Loc(LuaPlus::LuaState* state, gpg::StrArg key);

  /**
   * Engine addition.
   *
   * What it does:
   * Returns `text` with each "%s" replaced by the next of `args` (nothing once they run out) and each "%%" by one
   * '%'; any other '%' stays as it is. For a localized message that takes a player name: the binary passed the
   * localized text to printf as the format, and the text comes from loc files a mod can replace, so a '%' in a
   * translation read arguments that were never passed. Every shipped translation of these messages has one "%s".
   */
  [[nodiscard]] inline std::string LocFormat(
    const std::string_view text,
    const std::initializer_list<std::string_view> args
  )
  {
    std::string out;
    out.reserve(text.size());
    auto next = args.begin();
    for (std::size_t i = 0; i < text.size(); ++i) {
      if (text[i] == '%' && i + 1 < text.size()) {
        if (text[i + 1] == 's') {
          if (next != args.end()) {
            out += *next;
            ++next;
          }
          ++i;
          continue;
        }
        if (text[i + 1] == '%') {
          out += '%';
          ++i;
          continue;
        }
      }
      out += text[i];
    }
    return out;
  }
} // namespace moho
