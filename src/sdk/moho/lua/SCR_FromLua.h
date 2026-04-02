#pragma once

#include "lua/LuaObject.h"
#include "wm3/Vector3.h"

namespace moho
{
  template <typename TValue>
  TValue SCR_FromLuaCopy(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x004D0080 (FUN_004D0080, Moho::SCR_FromLuaCopy<Wm3::Vector3<float>>)
   *
   * What it does:
   * Reads Lua vector table entries `[1]`, `[2]`, `[3]` as `(x,y,z)` and
   * returns one copied `Wm3::Vector3f`.
   */
  template <>
  Wm3::Vector3<float> SCR_FromLuaCopy<Wm3::Vector3<float>>(const LuaPlus::LuaObject& object);
} // namespace moho

