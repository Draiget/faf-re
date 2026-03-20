#include "moho/lua/SCR_ToLua.h"

#include "moho/lua/CLuaVectorMetatableFactory.h"

/**
 * Address: 0x100C1240 (FUN_100C1240)
 *
 * LuaPlus::LuaState*, Wm3::Quaternion<float> const&
 *
 * IDA signature:
 * LuaPlus::LuaObject *__cdecl Moho::SCR_ToLua<Wm3::Quaternion<float>>(
 *     LuaPlus::LuaObject *result,
 *     LuaPlus::LuaState *state,
 *     float *quat
 * );
 *
 * What it does:
 * Builds a 4-slot Lua table in quaternion field order x,y,z,w
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
 * Address: 0x100C1410 (FUN_100C1410)
 *
 * LuaPlus::LuaState*, Wm3::Vector2<float> const&
 *
 * IDA signature:
 * LuaPlus::LuaObject *__cdecl Moho::SCR_ToLua<Wm3::Vector2<float>>(
 *     LuaPlus::LuaObject *result,
 *     LuaPlus::LuaState *state,
 *     float *vec2
 * );
 *
 * What it does:
 * Builds a 2-slot Lua table in x,y order and attaches
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
 * Address: 0x100C16D0 (FUN_100C16D0)
 *
 * LuaPlus::LuaState*, Wm3::Vector3<float> const&
 *
 * IDA signature:
 * LuaPlus::LuaObject *__cdecl Moho::SCR_ToLua<Wm3::Vector3<float>>(
 *     LuaPlus::LuaObject *result,
 *     LuaPlus::LuaState *state,
 *     float *vec3
 * );
 *
 * What it does:
 * Builds a 3-slot Lua table in x,y,z order and attaches
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
