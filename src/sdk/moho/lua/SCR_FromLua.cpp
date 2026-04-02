#include "moho/lua/SCR_FromLua.h"

/**
 * Address: 0x004D0080 (FUN_004D0080, Moho::SCR_FromLuaCopy<Wm3::Vector3<float>>)
 *
 * What it does:
 * Reads Lua vector table entries `[1]`, `[2]`, `[3]` as `(x,y,z)` and
 * returns one copied `Wm3::Vector3f`.
 */
template <>
Wm3::Vector3<float> moho::SCR_FromLuaCopy<Wm3::Vector3<float>>(const LuaPlus::LuaObject& object)
{
  Wm3::Vector3<float> out{};

  LuaPlus::LuaObject xObject = object[1];
  out.x = xObject.GetNumber();

  LuaPlus::LuaObject yObject = object[2];
  out.y = yObject.GetNumber();

  LuaPlus::LuaObject zObject = object[3];
  out.z = zObject.GetNumber();

  return out;
}

