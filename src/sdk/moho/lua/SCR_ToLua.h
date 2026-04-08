#pragma once

#include "gpg/core/containers/Rect2.h"
#include "lua/LuaObject.h"
#include "moho/ai/SPointVector.h"
#include "wm3/Quaternion.h"
#include "wm3/Vector2.h"
#include "wm3/Vector3.h"

namespace moho
{
  template <typename TValue>
  LuaPlus::LuaObject SCR_ToLua(LuaPlus::LuaState* state, const TValue& value);

  /**
   * Address: 0x004D08E0 (FUN_004D08E0, Moho::SCR_ToLua<gpg::Rect2<float>>)
   *
   * What it does:
   * Converts one Rect2f payload into a Lua hash table with keys
   * `x0`,`y0`,`x1`,`y1`.
   */
  template <>
  LuaPlus::LuaObject SCR_ToLua<gpg::Rect2<float>>(LuaPlus::LuaState* state, const gpg::Rect2<float>& value);

  /**
   * Address: 0x004D0990 (FUN_004D0990, Moho::SCR_ToLua<gpg::Rect2<int>>)
   *
   * What it does:
   * Converts one `Rect2i` payload into a Lua hash table with keys
   * `x0`,`y0`,`x1`,`y1`.
   */
  template <>
  LuaPlus::LuaObject SCR_ToLua<gpg::Rect2<int>>(LuaPlus::LuaState* state, const gpg::Rect2<int>& value);

  /**
   * Address: 0x004D0350 (FUN_004D0350, Moho::SCR_ToLua<Moho::SPointVector>)
   *
   * What it does:
   * Converts one `SPointVector` payload into a Lua hash table with keys
   * `px`,`py`,`pz`,`vx`,`vy`,`vz`.
   */
  template <>
  LuaPlus::LuaObject SCR_ToLua<SPointVector>(LuaPlus::LuaState* state, const SPointVector& value);

  /**
   * Address: 0x004CFB00 (FUN_004CFB00, Moho::SCR_ToLua<Wm3::Quaternion<float>>)
   *
   * What it does:
   * Converts quaternion value to Lua table payload and assigns
   * CLuaVectorMetatableFactory metatable.
   */
  template <>
  LuaPlus::LuaObject SCR_ToLua<Wm3::Quaternion<float>>(LuaPlus::LuaState* state, const Wm3::Quaternion<float>& value);

  /**
   * Address: 0x004CFCC0 (FUN_004CFCC0, Moho::SCR_ToLua<Wm3::Vector2<float>>)
   *
   * What it does:
   * Converts vec2 value to Lua table payload and assigns
   * CLuaVectorMetatableFactory metatable.
   */
  template <>
  LuaPlus::LuaObject SCR_ToLua<Wm3::Vector2<float>>(LuaPlus::LuaState* state, const Wm3::Vector2<float>& value);

  /**
   * Address: 0x004CFFC0 (FUN_004CFFC0, Moho::SCR_ToLua<Wm3::Vector3<float>>)
   *
   * What it does:
   * Converts vec3 value to Lua table payload and assigns
   * CLuaVectorMetatableFactory metatable.
   */
  template <>
  LuaPlus::LuaObject SCR_ToLua<Wm3::Vector3<float>>(LuaPlus::LuaState* state, const Wm3::Vector3<float>& value);
} // namespace moho
