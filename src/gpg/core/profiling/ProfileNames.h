#pragma once

// Engine addition: names for Tracy zones known only at run time. Profile builds only
// (TRACY_ENABLE); without Tracy nothing here exists and no caller compiles it in.
#if defined(TRACY_ENABLE)
#  include <string>
#  include <unordered_map>

namespace gpg::profiling
{
  /**
   * The engine's Lua C functions by address, as CScrLuaBinder registers them ("Unit:GetPosition",
   * "GetGameTick"). Filled while the binders are constructed, before the sim runs, and only read
   * after that, so lookups take no lock.
   */
  [[nodiscard]] inline std::unordered_map<const void*, std::string>& LuaCFunctionNames()
  {
    static std::unordered_map<const void*, std::string> names;
    return names;
  }

  /** Records `function`'s name; the first binder of a function names it. */
  inline void NameLuaCFunction(const void* const function, const char* const group, const char* const name)
  {
    if (function == nullptr || name == nullptr) {
      return;
    }
    const bool global = group == nullptr || group[0] == '\0' || std::string(group) == "<global>";
    LuaCFunctionNames().emplace(function, global ? std::string(name) : std::string(group) + ":" + name);
  }

  /** The zone name for a Lua C function: its binder's name, or a generic one. */
  [[nodiscard]] inline const char* LuaCFunctionName(const void* const function)
  {
    const auto& names = LuaCFunctionNames();
    const auto found = names.find(function);
    return found != names.end() ? found->second.c_str() : "lua C function (unnamed)";
  }
} // namespace gpg::profiling
#endif
