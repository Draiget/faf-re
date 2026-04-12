#pragma once

#include "gpg/core/containers/Rect2.h"
#include "lua/LuaObject.h"
#include "moho/ai/SPointVector.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace moho
{
  template <typename TValue>
  TValue SCR_FromLuaCopy(const LuaPlus::LuaObject& object);

  template <typename TValue>
  TValue* SCR_FromLuaCopy(const LuaPlus::LuaObject* object, TValue* outValue)
  {
    if (!outValue || !object) {
      return outValue;
    }

    *outValue = SCR_FromLuaCopy<TValue>(*object);
    return outValue;
  }

  /**
   * Address: 0x004D0A50 (FUN_004D0A50, Moho::SCR_FromLuaCopy<gpg::Rect2<float>>)
   *
   * What it does:
   * Reads Lua hash keys `x0`,`y0`,`x1`,`y1` and returns one copied `Rect2f`
   * (`y*` lanes map onto `z*` rectangle fields).
   */
  template <>
  gpg::Rect2<float> SCR_FromLuaCopy<gpg::Rect2<float>>(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x004D0B60 (FUN_004D0B60, Moho::SCR_FromLuaCopy<gpg::Rect2<int>>)
   *
   * What it does:
   * Reads Lua hash keys `x0`,`y0`,`x1`,`y1` and returns one copied `Rect2i`
   * (`y*` lanes map onto `z*` rectangle fields).
   */
  template <>
  gpg::Rect2<int> SCR_FromLuaCopy<gpg::Rect2<int>>(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x004CFBD0 (FUN_004CFBD0, Moho::SCR_FromLuaCopy<Wm3::Quaternion<float>>)
   *
   * What it does:
   * Reads Lua vector table entries `[1]`, `[2]`, `[3]`, `[4]` and returns one
   * copied quaternion where slots map to `(x,y,z,w)`.
   */
  template <>
  Wm3::Quaternion<float> SCR_FromLuaCopy<Wm3::Quaternion<float>>(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x004CFD70 (FUN_004CFD70, Moho::SCR_FromLuaCopy<Wm3::Vector2<float>>)
   *
   * What it does:
   * Reads Lua vector table entries `[1]`, `[2]` as `(x,y)` and returns one
   * copied `Wm3::Vector2f`.
   */
  template <>
  Wm3::Vector2<float> SCR_FromLuaCopy<Wm3::Vector2<float>>(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x004D0080 (FUN_004D0080, Moho::SCR_FromLuaCopy<Wm3::Vector3<float>>)
   *
   * What it does:
   * Reads Lua vector table entries `[1]`, `[2]`, `[3]` as `(x,y,z)` and
   * returns one copied `Wm3::Vector3f`.
   */
  template <>
  Wm3::Vector3<float> SCR_FromLuaCopy<Wm3::Vector3<float>>(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x004D0430 (FUN_004D0430, Moho::SCR_FromLuaCopy<Moho::SPointVector>)
   *
   * What it does:
   * Reads Lua hash keys `px`,`py`,`pz`,`vx`,`vy`,`vz` into one copied
   * `SPointVector` payload.
   */
  template <>
  SPointVector SCR_FromLuaCopy<SPointVector>(const LuaPlus::LuaObject& object);
} // namespace moho
