#include "moho/lua/SCR_FromLua.h"

/**
 * Address: 0x004D0A50 (FUN_004D0A50, Moho::SCR_FromLuaCopy<gpg::Rect2<float>>)
 *
 * What it does:
 * Reads Lua hash keys `x0`,`y0`,`x1`,`y1` and returns one copied `Rect2f`
 * (`y*` lanes map onto `z*` rectangle fields).
 */
template <>
gpg::Rect2<float> moho::SCR_FromLuaCopy<gpg::Rect2<float>>(const LuaPlus::LuaObject& object)
{
  gpg::Rect2<float> out{};

  LuaPlus::LuaObject x0Object = object.GetByName("x0");
  out.x0 = static_cast<float>(x0Object.GetNumber());

  LuaPlus::LuaObject y0Object = object.GetByName("y0");
  out.z0 = static_cast<float>(y0Object.GetNumber());

  LuaPlus::LuaObject x1Object = object.GetByName("x1");
  out.x1 = static_cast<float>(x1Object.GetNumber());

  LuaPlus::LuaObject y1Object = object.GetByName("y1");
  out.z1 = static_cast<float>(y1Object.GetNumber());

  return out;
}

/**
 * Address: 0x004D0B60 (FUN_004D0B60, Moho::SCR_FromLuaCopy<gpg::Rect2<int>>)
 *
 * What it does:
 * Reads Lua hash keys `x0`,`y0`,`x1`,`y1` and returns one copied `Rect2i`
 * (`y*` lanes map onto `z*` rectangle fields).
 */
template <>
gpg::Rect2<int> moho::SCR_FromLuaCopy<gpg::Rect2<int>>(const LuaPlus::LuaObject& object)
{
  gpg::Rect2<int> out{};

  LuaPlus::LuaObject x0Object = object.GetByName("x0");
  out.x0 = static_cast<int>(x0Object.GetNumber());

  LuaPlus::LuaObject y0Object = object.GetByName("y0");
  out.z0 = static_cast<int>(y0Object.GetNumber());

  LuaPlus::LuaObject x1Object = object.GetByName("x1");
  out.x1 = static_cast<int>(x1Object.GetNumber());

  LuaPlus::LuaObject y1Object = object.GetByName("y1");
  out.z1 = static_cast<int>(y1Object.GetNumber());

  return out;
}

/**
 * Address: 0x004CFBD0 (FUN_004CFBD0, Moho::SCR_FromLuaCopy<Wm3::Quaternion<float>>)
 *
 * What it does:
 * Reads Lua vector table entries `[1]`, `[2]`, `[3]`, `[4]` and returns one
 * copied quaternion where slots map to `(x,y,z,w)`.
 */
template <>
Wm3::Quaternion<float> moho::SCR_FromLuaCopy<Wm3::Quaternion<float>>(const LuaPlus::LuaObject& object)
{
  Wm3::Quaternion<float> out{};

  LuaPlus::LuaObject xObject = object[1];
  out.x = xObject.GetNumber();

  LuaPlus::LuaObject yObject = object[2];
  out.y = yObject.GetNumber();

  LuaPlus::LuaObject zObject = object[3];
  out.z = zObject.GetNumber();

  LuaPlus::LuaObject wObject = object[4];
  out.w = wObject.GetNumber();

  return out;
}

/**
 * Address: 0x004CFD70 (FUN_004CFD70, Moho::SCR_FromLuaCopy<Wm3::Vector2<float>>)
 *
 * What it does:
 * Reads Lua vector table entries `[1]`, `[2]` as `(x,y)` and returns one
 * copied `Wm3::Vector2f`.
 */
template <>
Wm3::Vector2<float> moho::SCR_FromLuaCopy<Wm3::Vector2<float>>(const LuaPlus::LuaObject& object)
{
  Wm3::Vector2<float> out{};

  LuaPlus::LuaObject xObject = object[1];
  out.x = xObject.GetNumber();

  LuaPlus::LuaObject yObject = object[2];
  out.y = yObject.GetNumber();

  return out;
}

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

/**
 * Address: 0x004D0430 (FUN_004D0430, Moho::SCR_FromLuaCopy<Moho::SPointVector>)
 *
 * What it does:
 * Reads Lua hash keys `px`,`py`,`pz`,`vx`,`vy`,`vz` into one copied
 * `SPointVector` payload.
 */
template <>
moho::SPointVector moho::SCR_FromLuaCopy<moho::SPointVector>(const LuaPlus::LuaObject& object)
{
  moho::SPointVector out{};

  LuaPlus::LuaObject pxObject = object.GetByName("px");
  out.point.x = pxObject.GetNumber();

  LuaPlus::LuaObject pyObject = object.GetByName("py");
  out.point.y = pyObject.GetNumber();

  LuaPlus::LuaObject pzObject = object.GetByName("pz");
  out.point.z = pzObject.GetNumber();

  LuaPlus::LuaObject vxObject = object.GetByName("vx");
  out.vector.x = vxObject.GetNumber();

  LuaPlus::LuaObject vyObject = object.GetByName("vy");
  out.vector.y = vyObject.GetNumber();

  LuaPlus::LuaObject vzObject = object.GetByName("vz");
  out.vector.z = vzObject.GetNumber();

  return out;
}
