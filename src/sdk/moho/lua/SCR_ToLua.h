#pragma once

#include "lua/LuaObject.h"
#include "wm3/Quaternion.h"
#include "wm3/Vector2.h"
#include "wm3/Vector3.h"

namespace moho
{
  template <typename TValue>
  LuaPlus::LuaObject SCR_ToLua(LuaPlus::LuaState* state, const TValue& value);

  /**
   * Address: 0x100C1240 (FUN_100C1240)
   *
   * LuaPlus::LuaState*, Wm3::Quaternion<float> const&
   *
   * What it does:
   * Converts quaternion value to Lua table payload and assigns
   * CLuaVectorMetatableFactory metatable.
   */
  template <>
  LuaPlus::LuaObject SCR_ToLua<Wm3::Quaternion<float>>(LuaPlus::LuaState* state, const Wm3::Quaternion<float>& value);

  /**
   * Address: 0x100C1410 (FUN_100C1410)
   *
   * LuaPlus::LuaState*, Wm3::Vector2<float> const&
   *
   * What it does:
   * Converts vec2 value to Lua table payload and assigns
   * CLuaVectorMetatableFactory metatable.
   */
  template <>
  LuaPlus::LuaObject SCR_ToLua<Wm3::Vector2<float>>(LuaPlus::LuaState* state, const Wm3::Vector2<float>& value);

  /**
   * Address: 0x100C16D0 (FUN_100C16D0)
   *
   * LuaPlus::LuaState*, Wm3::Vector3<float> const&
   *
   * What it does:
   * Converts vec3 value to Lua table payload and assigns
   * CLuaVectorMetatableFactory metatable.
   */
  template <>
  LuaPlus::LuaObject SCR_ToLua<Wm3::Vector3<float>>(LuaPlus::LuaState* state, const Wm3::Vector3<float>& value);
} // namespace moho
