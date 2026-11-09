#pragma once

// Engine addition: a Lua `{x, y, z}` table as a vector; anything else is zero.

#include "lua/LuaObject.h"
#include "moho/math/Vector3f.h"

namespace moho
{
  [[nodiscard]] inline Wm3::Vec3f ReadVector3FromLuaObject(const LuaPlus::LuaObject& object) noexcept
  {
    Wm3::Vec3f out = Wm3::Vec3f::Zero();
    if (!object.IsTable()) {
      return out;
    }

    const LuaPlus::LuaObject xObject = object[1];
    const LuaPlus::LuaObject yObject = object[2];
    const LuaPlus::LuaObject zObject = object[3];
    out.x = static_cast<float>(xObject.GetNumber());
    out.y = static_cast<float>(yObject.GetNumber());
    out.z = static_cast<float>(zObject.GetNumber());
    return out;
  }
} // namespace moho
