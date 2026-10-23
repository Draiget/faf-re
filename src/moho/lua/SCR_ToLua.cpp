#include "moho/lua/SCR_ToLua.h"

#include "moho/lua/CLuaVectorMetatableFactory.h"

/**
 * Address: 0x004D0350 (FUN_004D0350, Moho::SCR_ToLua<Moho::SPointVector>)
 *
 * What it does:
 * Builds a 6-key Lua hash table (`px`,`py`,`pz`,`vx`,`vy`,`vz`) from one
 * `SPointVector` payload.
 */
template <>
LuaPlus::LuaObject
moho::SCR_ToLua<moho::SPointVector>(LuaPlus::LuaState* const state, const moho::SPointVector& value)
{
  LuaPlus::LuaObject result;
  result.AssignNewTable(state, 0, 6);
  result.SetNumber("px", value.point.x);
  result.SetNumber("py", value.point.y);
  result.SetNumber("pz", value.point.z);
  result.SetNumber("vx", value.vector.x);
  result.SetNumber("vy", value.vector.y);
  result.SetNumber("vz", value.vector.z);
  return result;
}

/**
 * Address: 0x004D08E0 (FUN_004D08E0, Moho::SCR_ToLua<gpg::Rect2<float>>)
 *
 * What it does:
 * Builds a 4-key Lua hash table (`x0`,`y0`,`x1`,`y1`) from one `Rect2f`.
 */
template <>
LuaPlus::LuaObject
moho::SCR_ToLua<gpg::Rect2<float>>(LuaPlus::LuaState* const state, const gpg::Rect2<float>& value)
{
  LuaPlus::LuaObject result;
  result.AssignNewTable(state, 0, 4);
  result.SetNumber("x0", value.x0);
  result.SetNumber("y0", value.z0);
  result.SetNumber("x1", value.x1);
  result.SetNumber("y1", value.z1);
  return result;
}

/**
 * Address: 0x004D0990 (FUN_004D0990, Moho::SCR_ToLua<gpg::Rect2<int>>)
 *
 * What it does:
 * Builds a 4-key Lua hash table (`x0`,`y0`,`x1`,`y1`) from one `Rect2i`.
 */
template <>
LuaPlus::LuaObject
moho::SCR_ToLua<gpg::Rect2<int>>(LuaPlus::LuaState* const state, const gpg::Rect2<int>& value)
{
  LuaPlus::LuaObject result;
  result.AssignNewTable(state, 0, 4);
  result.SetNumber("x0", static_cast<float>(value.x0));
  result.SetNumber("y0", static_cast<float>(value.z0));
  result.SetNumber("x1", static_cast<float>(value.x1));
  result.SetNumber("y1", static_cast<float>(value.z1));
  return result;
}

/**
 * Address: 0x004CFB00 (FUN_004CFB00, Moho::SCR_ToLua<Wm3::Quaternion<float>>)
 *
 * What it does:
 * Builds a 4-slot Lua table in quaternion field order `x,y,z,w`
 * and attaches the shared vector metatable.
 */
template <>
LuaPlus::LuaObject
moho::SCR_ToLua<Wm3::Quaternion<float>>(LuaPlus::LuaState* const state, const Wm3::Quaternion<float>& value)
{
  LuaPlus::LuaObject result;
  result.AssignNewTable(state, 4, 0);
  result.SetNumber(1, value.x);
  result.SetNumber(2, value.y);
  result.SetNumber(3, value.z);
  result.SetNumber(4, value.w);

  const LuaPlus::LuaObject metatable = CLuaVectorMetatableFactory::Instance().Get(state);
  result.SetMetaTable(metatable);
  return result;
}

/**
 * Address: 0x004CFCC0 (FUN_004CFCC0, Moho::SCR_ToLua<Wm3::Vector2<float>>)
 *
 * What it does:
 * Builds a 2-slot Lua table in `x,y` order and attaches
 * the shared vector metatable.
 */
template <>
LuaPlus::LuaObject
moho::SCR_ToLua<Wm3::Vector2<float>>(LuaPlus::LuaState* const state, const Wm3::Vector2<float>& value)
{
  LuaPlus::LuaObject result;
  result.AssignNewTable(state, 2, 0);
  result.SetNumber(1, value.x);
  result.SetNumber(2, value.y);

  const LuaPlus::LuaObject metatable = CLuaVectorMetatableFactory::Instance().Get(state);
  result.SetMetaTable(metatable);
  return result;
}

/**
 * Address: 0x004CFFC0 (FUN_004CFFC0, Moho::SCR_ToLua<Wm3::Vector3<float>>)
 *
 * What it does:
 * Builds a 3-slot Lua table in `x,y,z` order and attaches
 * the shared vector metatable.
 */
template <>
LuaPlus::LuaObject
moho::SCR_ToLua<Wm3::Vector3<float>>(LuaPlus::LuaState* const state, const Wm3::Vector3<float>& value)
{
  LuaPlus::LuaObject result;
  result.AssignNewTable(state, 3, 0);
  result.SetNumber(1, value.x);
  result.SetNumber(2, value.y);
  result.SetNumber(3, value.z);

  const LuaPlus::LuaObject metatable = CLuaVectorMetatableFactory::Instance().Get(state);
  result.SetMetaTable(metatable);
  return result;
}
