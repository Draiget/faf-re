#include "moho/lua/SCR_Math.h"

#include <cmath>

#include "lua/LuaObject.h"
#include "moho/entity/Entity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/math/MathReflection.h"

namespace
{
  constexpr const char* kVectorHelpText = "Create a vector (x,y,z)";
  constexpr const char* kVector2HelpText = "Create a vector (x,y)";
  constexpr const char* kPointVectorHelpText = "Create a point vector(px,py,pz, vx,vy,vz)";
  constexpr const char* kOrientFromDirHelpText = "quaternion OrientFromDir(vector)";
  constexpr const char* kEulerToQuaternionHelpText =
    "quaternion EulerToQuaternion(float roll, float pitch, float yaw) - converts euler angles to a quaternion";
  constexpr const char* kMinLerpHelpText =
    "quaternion MinLerp(float alpha, quaternion L, quaternion R) - returns minimal lerp between L and R";
  constexpr const char* kMinSlerpHelpText =
    "quaternion MinSlerp(float alpha, quaternion L, quaternion R) - returns minimal slerp between L and R";
  constexpr const char* kRectHelpText = "Create a 2d Rectangle (x0,y0,x1,y1)";
  constexpr const char* kVDist3HelpText = "Distance between two 3d points (v1,v2)";
  constexpr const char* kVDist3SqHelpText = "Square of Distance between two 3d points (v1,v2)";
  constexpr const char* kVDist2HelpText = "Distance between two 2d points (x1,y1,x2,y2)";
  constexpr const char* kVDist2SqHelpText = "Square of Distance between two 2d points (x1,y1,x2,y2)";
  constexpr const char* kVDotHelpText = "Dot product of two vectors";
  constexpr const char* kVDiffHelpText = "Difference of two vectors";
  constexpr const char* kVAddHelpText = "Addition of two vectors";
  constexpr const char* kVMultHelpText = "Multiplication of vector with scalar";
  constexpr const char* kVPerpDotHelpText = "Perp dot product of two vectors";
  constexpr const char* kMathIRoundHelpText = "Round a number to the nearest integer";
  constexpr const char* kMathLerpHelpText =
    "MATH_Lerp(s, a, b) or MATH_Lerp(s, sMin, sMax, a, b) -> number -- linear interpolation from a (at s=0 or "
    "s=sMin) to b (at s=1 or s=sMax)";

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
  }

} // namespace

/**
 * Address: 0x0050D3B0 (FUN_0050D3B0, cfunc_OrientFromDir)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_OrientFromDirL`.
 */
int moho::cfunc_OrientFromDir(lua_State* const luaContext)
{
  return cfunc_OrientFromDirL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0050D430 (FUN_0050D430, cfunc_OrientFromDirL)
 *
 * What it does:
 * Implements global `OrientFromDir(vector)` and returns a quaternion Lua
 * object.
 */
int moho::cfunc_OrientFromDirL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kOrientFromDirHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject argument(state, 1);
  LuaPlus::LuaObject directionObject(argument);
  Wm3::Vec3f direction{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&directionObject, &direction);

  const Wm3::Quatf orientation = moho::COORDS_Orient(direction);
  LuaPlus::LuaObject luaOrientation = SCR_ToLua<Wm3::Quaternion<float>>(state, orientation);
  luaOrientation.PushStack(state);
  return 1;
}

/**
 * Address: 0x0050D3D0 (FUN_0050D3D0, func_OrientFromDir_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `OrientFromDir`.
 */
moho::CScrLuaInitForm* moho::func_OrientFromDir_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "OrientFromDir",
    &moho::cfunc_OrientFromDir,
    nullptr,
    "<global>",
    kOrientFromDirHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC7F10 (FUN_00BC7F10, register_OrientFromDir_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_OrientFromDir_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_OrientFromDir_LuaFuncDef()
{
  return func_OrientFromDir_LuaFuncDef();
}

/**
 * Address: 0x0050D510 (FUN_0050D510, cfunc_EulerToQuaternion)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_EulerToQuaternionL`.
 */
int moho::cfunc_EulerToQuaternion(lua_State* const luaContext)
{
  return cfunc_EulerToQuaternionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0050D590 (FUN_0050D590, cfunc_EulerToQuaternionL)
 *
 * What it does:
 * Implements global `EulerToQuaternion(float roll, float pitch, float yaw)`
 * and returns a quaternion Lua object.
 */
int moho::cfunc_EulerToQuaternionL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected %d args, but got %d",
      kEulerToQuaternionHelpText,
      3,
      argumentCount
    );
  }

  LuaPlus::LuaStackObject rollArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&rollArg, "number");
  }
  const float roll = static_cast<float>(lua_tonumber(state->m_state, 1));

  LuaPlus::LuaStackObject pitchArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&pitchArg, "number");
  }
  const float pitch = static_cast<float>(lua_tonumber(state->m_state, 2));

  LuaPlus::LuaStackObject yawArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&yawArg, "number");
  }
  const float yaw = static_cast<float>(lua_tonumber(state->m_state, 3));

  const VEulers3 eulerAngles{roll, pitch, yaw};
  const Wm3::Quatf orientation = moho::EulerToQuaternion(eulerAngles);
  LuaPlus::LuaObject luaOrientation = SCR_ToLua<Wm3::Quaternion<float>>(state, orientation);
  luaOrientation.PushStack(state);
  return 1;
}

/**
 * Address: 0x0050D530 (FUN_0050D530, func_EulerToQuaternion_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EulerToQuaternion`.
 */
moho::CScrLuaInitForm* moho::func_EulerToQuaternion_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "EulerToQuaternion",
    &moho::cfunc_EulerToQuaternion,
    nullptr,
    "<global>",
    kEulerToQuaternionHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC7F20 (FUN_00BC7F20, register_EulerToQuaternion_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_EulerToQuaternion_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_EulerToQuaternion_LuaFuncDef()
{
  return func_EulerToQuaternion_LuaFuncDef();
}

/**
 * Address: 0x0050D730 (FUN_0050D730, cfunc_MinLerp)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_MinLerpL`.
 */
int moho::cfunc_MinLerp(lua_State* const luaContext)
{
  return cfunc_MinLerpL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0050D7B0 (FUN_0050D7B0, cfunc_MinLerpL)
 *
 * What it does:
 * Implements global `MinLerp(float alpha, quaternion L, quaternion R)` and
 * returns the shortest-path normalized lerp of the input quaternions.
 */
int moho::cfunc_MinLerpL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kMinLerpHelpText, 3, argumentCount);
  }

  LuaPlus::LuaStackObject alphaArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&alphaArg, "number");
  }
  const float alpha = static_cast<float>(lua_tonumber(state->m_state, 1));

  LuaPlus::LuaStackObject leftArg(state, 2);
  LuaPlus::LuaObject leftObject(leftArg);
  Wm3::Quatf left{};
  SCR_FromLuaCopy<Wm3::Quaternion<float>>(&leftObject, &left);

  LuaPlus::LuaStackObject rightArg(state, 3);
  LuaPlus::LuaObject rightObject(rightArg);
  Wm3::Quatf right{};
  SCR_FromLuaCopy<Wm3::Quaternion<float>>(&rightObject, &right);

  const Wm3::Quatf interpolated = Wm3::Quatf::Nlerp(left, right, alpha);
  LuaPlus::LuaObject luaOrientation = SCR_ToLua<Wm3::Quaternion<float>>(state, interpolated);
  luaOrientation.PushStack(state);
  return 1;
}

/**
 * Address: 0x0050D750 (FUN_0050D750, func_MinLerp_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `MinLerp`.
 */
moho::CScrLuaInitForm* moho::func_MinLerp_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "MinLerp",
    &moho::cfunc_MinLerp,
    nullptr,
    "<global>",
    kMinLerpHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC7F30 (FUN_00BC7F30, register_MinLerp_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_MinLerp_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_MinLerp_LuaFuncDef()
{
  return func_MinLerp_LuaFuncDef();
}

/**
 * Address: 0x0050D950 (FUN_0050D950, cfunc_MinSlerp)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_MinSlerpL`.
 */
int moho::cfunc_MinSlerp(lua_State* const luaContext)
{
  return cfunc_MinSlerpL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0050D9D0 (FUN_0050D9D0, cfunc_MinSlerpL)
 *
 * What it does:
 * Implements global `MinSlerp(float alpha, quaternion L, quaternion R)` and
 * returns the shortest-path spherical interpolation of the input quaternions.
 */
int moho::cfunc_MinSlerpL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kMinSlerpHelpText, 3, argumentCount);
  }

  LuaPlus::LuaStackObject alphaArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&alphaArg, "number");
  }
  const float alpha = static_cast<float>(lua_tonumber(state->m_state, 1));

  LuaPlus::LuaStackObject leftArg(state, 2);
  LuaPlus::LuaObject leftObject(leftArg);
  Wm3::Quatf left{};
  SCR_FromLuaCopy<Wm3::Quaternion<float>>(&leftObject, &left);

  LuaPlus::LuaStackObject rightArg(state, 3);
  LuaPlus::LuaObject rightObject(rightArg);
  Wm3::Quatf right{};
  SCR_FromLuaCopy<Wm3::Quaternion<float>>(&rightObject, &right);

  const Wm3::Quatf interpolated = Wm3::Quatf::Slerp(left, right, alpha);
  LuaPlus::LuaObject luaOrientation = SCR_ToLua<Wm3::Quaternion<float>>(state, interpolated);
  luaOrientation.PushStack(state);
  return 1;
}

/**
 * Address: 0x0050D970 (FUN_0050D970, func_MinSlerp_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `MinSlerp`.
 */
moho::CScrLuaInitForm* moho::func_MinSlerp_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "MinSlerp",
    &moho::cfunc_MinSlerp,
    nullptr,
    "<global>",
    kMinSlerpHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC7F40 (FUN_00BC7F40, register_MinSlerp_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_MinSlerp_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_MinSlerp_LuaFuncDef()
{
  return func_MinSlerp_LuaFuncDef();
}

/**
 * Address: 0x004D0140 (FUN_004D0140, cfunc_Vector)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_VectorL`.
 */
int moho::cfunc_Vector(lua_State* const luaContext)
{
  return cfunc_VectorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D01C0 (FUN_004D01C0, cfunc_VectorL)
 *
 * What it does:
 * Implements global `Vector(x, y, z)` and returns a Vector3f Lua object.
 */
int moho::cfunc_VectorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kVectorHelpText, 3, argumentCount);
  }

  LuaPlus::LuaStackObject xArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }
  const float x = static_cast<float>(lua_tonumber(state->m_state, 1));

  LuaPlus::LuaStackObject yArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&yArg, "number");
  }
  const float y = static_cast<float>(lua_tonumber(state->m_state, 2));

  LuaPlus::LuaStackObject zArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "number");
  }
  const float z = static_cast<float>(lua_tonumber(state->m_state, 3));

  const Wm3::Vec3f vector{x, y, z};
  LuaPlus::LuaObject vectorObject = SCR_ToLua(state, vector);
  vectorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x004D0160 (FUN_004D0160, func_Vector_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `Vector`.
 */
moho::CScrLuaInitForm* moho::func_Vector_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "Vector",
    &moho::cfunc_Vector,
    nullptr,
    "<global>",
    kVectorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC64E0 (FUN_00BC64E0, register_Vector_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_Vector_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_Vector_LuaFuncDef()
{
  return func_Vector_LuaFuncDef();
}

/**
 * Address: 0x004CFE00 (FUN_004CFE00, cfunc_Vector2)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_Vector2L`.
 */
int moho::cfunc_Vector2(lua_State* const luaContext)
{
  return cfunc_Vector2L(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004CFE80 (FUN_004CFE80, cfunc_Vector2L)
 *
 * What it does:
 * Implements global `Vector2(x, y)` and returns a Vector2f Lua object.
 */
int moho::cfunc_Vector2L(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kVector2HelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject xArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }

  LuaPlus::LuaStackObject yArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&yArg, "number");
  }

  const Wm3::Vector2<float>
    vector2{static_cast<float>(lua_tonumber(state->m_state, 1)), static_cast<float>(lua_tonumber(state->m_state, 2))};
  LuaPlus::LuaObject vectorObject = SCR_ToLua<Wm3::Vector2<float>>(state, vector2);
  vectorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x004CFE20 (FUN_004CFE20, func_Vector2_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `Vector2`.
 */
moho::CScrLuaInitForm* moho::func_Vector2_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "Vector2",
    &moho::cfunc_Vector2,
    nullptr,
    "<global>",
    kVector2HelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC64D0 (FUN_00BC64D0, register_Vector2_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_Vector2_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_Vector2_LuaFuncDef()
{
  return func_Vector2_LuaFuncDef();
}

/**
 * Address: 0x004D0600 (FUN_004D0600, cfunc_PointVector)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_PointVectorL`.
 */
int moho::cfunc_PointVector(lua_State* const luaContext)
{
  return cfunc_PointVectorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D0680 (FUN_004D0680, cfunc_PointVectorL)
 *
 * What it does:
 * Implements global `PointVector(px, py, pz, vx, vy, vz)` and returns one
 * `SPointVector` Lua object.
 */
int moho::cfunc_PointVectorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 6) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kPointVectorHelpText, 6, argumentCount);
  }

  moho::SPointVector pointVector{};
  for (int index = 1; index <= 6; ++index) {
    LuaPlus::LuaStackObject arg(state, index);
    if (lua_type(state->m_state, index) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&arg, "number");
    }
  }

  pointVector.point.x = static_cast<float>(lua_tonumber(state->m_state, 1));
  pointVector.point.y = static_cast<float>(lua_tonumber(state->m_state, 2));
  pointVector.point.z = static_cast<float>(lua_tonumber(state->m_state, 3));
  pointVector.vector.x = static_cast<float>(lua_tonumber(state->m_state, 4));
  pointVector.vector.y = static_cast<float>(lua_tonumber(state->m_state, 5));
  pointVector.vector.z = static_cast<float>(lua_tonumber(state->m_state, 6));

  LuaPlus::LuaObject pointVectorObject = SCR_ToLua<moho::SPointVector>(state, pointVector);
  pointVectorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x004D0620 (FUN_004D0620, func_PointVector_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `PointVector`.
 */
moho::CScrLuaInitForm* moho::func_PointVector_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "PointVector",
    &moho::cfunc_PointVector,
    nullptr,
    "<global>",
    kPointVectorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC64F0 (FUN_00BC64F0, register_PointVector_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_PointVector_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_PointVector_LuaFuncDef()
{
  return func_PointVector_LuaFuncDef();
}

/**
 * Address: 0x004D0C70 (FUN_004D0C70, cfunc_Rect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_RectL`.
 */
int moho::cfunc_Rect(lua_State* const luaContext)
{
  return cfunc_RectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D0CF0 (FUN_004D0CF0, cfunc_RectL)
 *
 * What it does:
 * Implements global `Rect(x0, y0, x1, y1)` and returns a Rect2f Lua table.
 */
int moho::cfunc_RectL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kRectHelpText, 4, argumentCount);
  }

  LuaPlus::LuaStackObject x0Arg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&x0Arg, "number");
  }

  LuaPlus::LuaStackObject y0Arg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&y0Arg, "number");
  }

  LuaPlus::LuaStackObject x1Arg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&x1Arg, "number");
  }

  LuaPlus::LuaStackObject y1Arg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&y1Arg, "number");
  }

  gpg::Rect2<float> rect{
    static_cast<float>(lua_tonumber(state->m_state, 1)),
    static_cast<float>(lua_tonumber(state->m_state, 2)),
    static_cast<float>(lua_tonumber(state->m_state, 3)),
    static_cast<float>(lua_tonumber(state->m_state, 4)),
  };

  LuaPlus::LuaObject rectObject = SCR_ToLua(state, rect);
  rectObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x004D0C90 (FUN_004D0C90, func_Rect_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `Rect`.
 */
moho::CScrLuaInitForm* moho::func_Rect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "Rect",
    &moho::cfunc_Rect,
    nullptr,
    "<global>",
    kRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6500 (FUN_00BC6500, register_Rect_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_Rect_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_Rect_LuaFuncDef()
{
  return func_Rect_LuaFuncDef();
}

/**
 * Address: 0x004D0EB0 (FUN_004D0EB0, cfunc_VDist3)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_VDist3L`.
 */
int moho::cfunc_VDist3(lua_State* const luaContext)
{
  return cfunc_VDist3L(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D0F30 (FUN_004D0F30, cfunc_VDist3L)
 *
 * What it does:
 * Validates two `Vector3f` Lua arguments and returns Euclidean 3D distance.
 */
int moho::cfunc_VDist3L(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kVDist3HelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject rightArg(state, 2);
  LuaPlus::LuaObject rightObject(rightArg);
  Wm3::Vec3f right{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&rightObject, &right);

  LuaPlus::LuaStackObject leftArg(state, 1);
  LuaPlus::LuaObject leftObject(leftArg);
  Wm3::Vec3f left{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&leftObject, &left);

  const float dx = left.x - right.x;
  const float dy = left.y - right.y;
  const float dz = left.z - right.z;
  lua_pushnumber(state->m_state, std::sqrt((dx * dx) + (dy * dy) + (dz * dz)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D0ED0 (FUN_004D0ED0, func_VDist3_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `VDist3`.
 */
moho::CScrLuaInitForm* moho::func_VDist3_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "VDist3",
    &moho::cfunc_VDist3,
    nullptr,
    "<global>",
    kVDist3HelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6510 (FUN_00BC6510, register_VDist3_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_VDist3_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_VDist3_LuaFuncDef()
{
  return func_VDist3_LuaFuncDef();
}

/**
 * Address: 0x004D1070 (FUN_004D1070, cfunc_VDist3Sq)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_VDist3SqL`.
 */
int moho::cfunc_VDist3Sq(lua_State* const luaContext)
{
  return cfunc_VDist3SqL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D10F0 (FUN_004D10F0, cfunc_VDist3SqL)
 *
 * What it does:
 * Validates two `Vector3f` Lua arguments and returns squared 3D distance.
 */
int moho::cfunc_VDist3SqL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kVDist3SqHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject rightArg(state, 2);
  LuaPlus::LuaObject rightObject(rightArg);
  Wm3::Vec3f right{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&rightObject, &right);

  LuaPlus::LuaStackObject leftArg(state, 1);
  LuaPlus::LuaObject leftObject(leftArg);
  Wm3::Vec3f left{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&leftObject, &left);

  const float dx = left.x - right.x;
  const float dy = left.y - right.y;
  const float dz = left.z - right.z;
  lua_pushnumber(state->m_state, (dx * dx) + (dy * dy) + (dz * dz));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D1090 (FUN_004D1090, func_VDist3Sq_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `VDist3Sq`.
 */
moho::CScrLuaInitForm* moho::func_VDist3Sq_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "VDist3Sq",
    &moho::cfunc_VDist3Sq,
    nullptr,
    "<global>",
    kVDist3SqHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6520 (FUN_00BC6520, register_VDist3Sq_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_VDist3Sq_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_VDist3Sq_LuaFuncDef()
{
  return func_VDist3Sq_LuaFuncDef();
}

/**
 * Address: 0x004D1230 (FUN_004D1230, cfunc_VDist2)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_VDist2L`.
 */
int moho::cfunc_VDist2(lua_State* const luaContext)
{
  return cfunc_VDist2L(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D12B0 (FUN_004D12B0, cfunc_VDist2L)
 *
 * What it does:
 * Validates `(x1, y1, x2, y2)` number arguments and returns Euclidean
 * 2D distance.
 */
int moho::cfunc_VDist2L(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kVDist2HelpText, 4, argumentCount);
  }

  LuaPlus::LuaStackObject y1Arg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&y1Arg, "number");
  }
  const float y1 = static_cast<float>(lua_tonumber(state->m_state, 2));

  LuaPlus::LuaStackObject x1Arg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&x1Arg, "number");
  }
  const float x1 = static_cast<float>(lua_tonumber(state->m_state, 1));

  LuaPlus::LuaStackObject y2Arg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&y2Arg, "number");
  }
  const float y2 = static_cast<float>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject x2Arg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&x2Arg, "number");
  }
  const float x2 = static_cast<float>(lua_tonumber(state->m_state, 3));

  const float dy = y1 - y2;
  const float dx = x1 - x2;
  const float distance = std::sqrt((dy * dy) + (dx * dx));
  lua_pushnumber(state->m_state, distance);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D1250 (FUN_004D1250, func_VDist2_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `VDist2`.
 */
moho::CScrLuaInitForm* moho::func_VDist2_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "VDist2",
    &moho::cfunc_VDist2,
    nullptr,
    "<global>",
    kVDist2HelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6530 (FUN_00BC6530, register_VDist2_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_VDist2_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_VDist2_LuaFuncDef()
{
  return func_VDist2_LuaFuncDef();
}

/**
 * Address: 0x004D1440 (FUN_004D1440, cfunc_VDist2Sq)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_VDist2SqL`.
 */
int moho::cfunc_VDist2Sq(lua_State* const luaContext)
{
  return cfunc_VDist2SqL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D14C0 (FUN_004D14C0, cfunc_VDist2SqL)
 *
 * What it does:
 * Validates `(x1, y1, x2, y2)` number arguments and returns squared 2D
 * distance.
 */
int moho::cfunc_VDist2SqL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kVDist2SqHelpText, 4, argumentCount);
  }

  LuaPlus::LuaStackObject y1Arg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&y1Arg, "number");
  }
  const float y1 = static_cast<float>(lua_tonumber(state->m_state, 2));

  LuaPlus::LuaStackObject x1Arg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&x1Arg, "number");
  }
  const float x1 = static_cast<float>(lua_tonumber(state->m_state, 1));

  LuaPlus::LuaStackObject y2Arg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&y2Arg, "number");
  }
  const float y2 = static_cast<float>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject x2Arg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&x2Arg, "number");
  }
  const float x2 = static_cast<float>(lua_tonumber(state->m_state, 3));

  const float dy = y1 - y2;
  const float dx = x1 - x2;
  lua_pushnumber(state->m_state, (dy * dy) + (dx * dx));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D1460 (FUN_004D1460, func_VDist2Sq_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `VDist2Sq`.
 */
moho::CScrLuaInitForm* moho::func_VDist2Sq_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "VDist2Sq",
    &moho::cfunc_VDist2Sq,
    nullptr,
    "<global>",
    kVDist2SqHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6540 (FUN_00BC6540, register_VDist2Sq_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_VDist2Sq_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_VDist2Sq_LuaFuncDef()
{
  return func_VDist2Sq_LuaFuncDef();
}

/**
 * Address: 0x004D1650 (FUN_004D1650, cfunc_VDot)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_VDotL`.
 */
int moho::cfunc_VDot(lua_State* const luaContext)
{
  return cfunc_VDotL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D16D0 (FUN_004D16D0, cfunc_VDotL)
 *
 * What it does:
 * Validates two `Vector3f` Lua arguments and returns their dot product.
 */
int moho::cfunc_VDotL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kVDotHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject rightArg(state, 2);
  LuaPlus::LuaObject rightObject(rightArg);
  Wm3::Vec3f right{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&rightObject, &right);

  LuaPlus::LuaStackObject leftArg(state, 1);
  LuaPlus::LuaObject leftObject(leftArg);
  Wm3::Vec3f left{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&leftObject, &left);

  lua_pushnumber(state->m_state, (left.x * right.x) + (left.y * right.y) + (left.z * right.z));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D1670 (FUN_004D1670, func_VDot_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `VDot`.
 */
moho::CScrLuaInitForm* moho::func_VDot_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "VDot",
    &moho::cfunc_VDot,
    nullptr,
    "<global>",
    kVDotHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6550 (FUN_00BC6550, register_VDot_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_VDot_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_VDot_LuaFuncDef()
{
  return func_VDot_LuaFuncDef();
}

/**
 * Address: 0x004D17E0 (FUN_004D17E0, cfunc_VDiff)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_VDiffL`.
 */
int moho::cfunc_VDiff(lua_State* const luaContext)
{
  return cfunc_VDiffL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D1860 (FUN_004D1860, cfunc_VDiffL)
 *
 * What it does:
 * Validates two `Vector3f` Lua arguments and returns their difference.
 */
int moho::cfunc_VDiffL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kVDiffHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject rightArg(state, 2);
  LuaPlus::LuaObject rightObject(rightArg);
  Wm3::Vec3f right{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&rightObject, &right);

  LuaPlus::LuaStackObject leftArg(state, 1);
  LuaPlus::LuaObject leftObject(leftArg);
  Wm3::Vec3f left{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&leftObject, &left);

  const Wm3::Vec3f result{left.x - right.x, left.y - right.y, left.z - right.z};
  LuaPlus::LuaObject luaResult = SCR_ToLua<Wm3::Vector3<float>>(state, result);
  luaResult.PushStack(state);
  return 1;
}

/**
 * Address: 0x004D1800 (FUN_004D1800, func_VDiff_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `VDiff`.
 */
moho::CScrLuaInitForm* moho::func_VDiff_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "VDiff",
    &moho::cfunc_VDiff,
    nullptr,
    "<global>",
    kVDiffHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6560 (FUN_00BC6560, register_VDiff_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_VDiff_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_VDiff_LuaFuncDef()
{
  return func_VDiff_LuaFuncDef();
}

/**
 * Address: 0x004D19C0 (FUN_004D19C0, cfunc_VAdd)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_VAddL`.
 */
int moho::cfunc_VAdd(lua_State* const luaContext)
{
  return cfunc_VAddL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D1A40 (FUN_004D1A40, cfunc_VAddL)
 *
 * What it does:
 * Validates two `Vector3f` Lua arguments and returns their sum.
 */
int moho::cfunc_VAddL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kVAddHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject rightArg(state, 2);
  LuaPlus::LuaObject rightObject(rightArg);
  Wm3::Vec3f right{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&rightObject, &right);

  LuaPlus::LuaStackObject leftArg(state, 1);
  LuaPlus::LuaObject leftObject(leftArg);
  Wm3::Vec3f left{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&leftObject, &left);

  const Wm3::Vec3f result{left.x + right.x, left.y + right.y, left.z + right.z};
  LuaPlus::LuaObject luaResult = SCR_ToLua<Wm3::Vector3<float>>(state, result);
  luaResult.PushStack(state);
  return 1;
}

/**
 * Address: 0x004D19E0 (FUN_004D19E0, func_VAdd_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `VAdd`.
 */
moho::CScrLuaInitForm* moho::func_VAdd_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "VAdd",
    &moho::cfunc_VAdd,
    nullptr,
    "<global>",
    kVAddHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6570 (FUN_00BC6570, register_VAdd_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_VAdd_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_VAdd_LuaFuncDef()
{
  return func_VAdd_LuaFuncDef();
}

/**
 * Address: 0x004D1BA0 (FUN_004D1BA0, cfunc_VMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_VMultL`.
 */
int moho::cfunc_VMult(lua_State* const luaContext)
{
  return cfunc_VMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D1C20 (FUN_004D1C20, cfunc_VMultL)
 *
 * What it does:
 * Multiplies one `Vector3f` by one scalar and returns the resulting vector.
 */
int moho::cfunc_VMultL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kVMultHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject vectorArg(state, 1);
  LuaPlus::LuaObject vectorObject(vectorArg);
  Wm3::Vec3f vector{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&vectorObject, &vector);

  LuaPlus::LuaStackObject scalarArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&scalarArg, "number");
  }

  const float scalar = static_cast<float>(lua_tonumber(state->m_state, 2));
  const Wm3::Vec3f result{vector.x * scalar, vector.y * scalar, vector.z * scalar};
  LuaPlus::LuaObject luaResult = SCR_ToLua<Wm3::Vector3<float>>(state, result);
  luaResult.PushStack(state);
  return 1;
}

/**
 * Address: 0x004D1BC0 (FUN_004D1BC0, func_VMult_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `VMult`.
 */
moho::CScrLuaInitForm* moho::func_VMult_LuaFuncDef()
{
  static CScrLuaBinder binder(CoreLuaInitSet(), "VMult", &moho::cfunc_VMult, nullptr, "<global>", kVMultHelpText);
  return &binder;
}

/**
 * Address: 0x00BC6580 (FUN_00BC6580, register_VMult_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_VMult_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_VMult_LuaFuncDef()
{
  return func_VMult_LuaFuncDef();
}

/**
 * Address: 0x004D1D70 (FUN_004D1D70, cfunc_VPerpDot)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_VPerpDotL`.
 */
int moho::cfunc_VPerpDot(lua_State* const luaContext)
{
  return cfunc_VPerpDotL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D1DF0 (FUN_004D1DF0, cfunc_VPerpDotL)
 *
 * What it does:
 * Computes the 2D perpendicular-dot lane from two vectors:
 * `x1 * z2 - x2 * z1`.
 */
int moho::cfunc_VPerpDotL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kVPerpDotHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject secondVectorArg(state, 2);
  LuaPlus::LuaObject secondVectorObject(secondVectorArg);
  Wm3::Vec3f secondVector{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&secondVectorObject, &secondVector);

  LuaPlus::LuaStackObject firstVectorArg(state, 1);
  LuaPlus::LuaObject firstVectorObject(firstVectorArg);
  Wm3::Vec3f firstVector{};
  SCR_FromLuaCopy<Wm3::Vector3<float>>(&firstVectorObject, &firstVector);

  const float perpDot = (firstVector.x * secondVector.z) - (secondVector.x * firstVector.z);
  lua_pushnumber(state->m_state, perpDot);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D1D90 (FUN_004D1D90, func_VPerpDot_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `VPerpDot`.
 */
moho::CScrLuaInitForm* moho::func_VPerpDot_LuaFuncDef()
{
  static CScrLuaBinder
    binder(CoreLuaInitSet(), "VPerpDot", &moho::cfunc_VPerpDot, nullptr, "<global>", kVPerpDotHelpText);
  return &binder;
}

/**
 * Address: 0x00BC6590 (FUN_00BC6590, register_VPerpDot_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_VPerpDot_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_VPerpDot_LuaFuncDef()
{
  return func_VPerpDot_LuaFuncDef();
}

/**
 * Address: 0x004D1F10 (FUN_004D1F10, cfunc_MATH_IRound)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_MATH_IRoundL`.
 */
int moho::cfunc_MATH_IRound(lua_State* const luaContext)
{
  return cfunc_MATH_IRoundL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D1F90 (FUN_004D1F90, cfunc_MATH_IRoundL)
 *
 * What it does:
 * Converts one numeric Lua argument to an integer lane and returns it as a
 * Lua number.
 */
int moho::cfunc_MATH_IRoundL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kMathIRoundHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject numberArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&numberArg, "number");
  }

  const float value = static_cast<float>(lua_tonumber(state->m_state, 1));
  lua_pushnumber(state->m_state, static_cast<float>(static_cast<int>(value)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D1F30 (FUN_004D1F30, func_MATH_IRound_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `MATH_IRound`.
 */
moho::CScrLuaInitForm* moho::func_MATH_IRound_LuaFuncDef()
{
  static CScrLuaBinder
    binder(CoreLuaInitSet(), "MATH_IRound", &moho::cfunc_MATH_IRound, nullptr, "<global>", kMathIRoundHelpText);
  return &binder;
}

/**
 * Address: 0x00BC65A0 (FUN_00BC65A0, register_MATH_IRound_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_MATH_IRound_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_MATH_IRound_LuaFuncDef()
{
  return func_MATH_IRound_LuaFuncDef();
}

/**
 * Address: 0x004D2030 (FUN_004D2030, cfunc_MATH_lerp)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_MATH_lerpL`.
 */
int moho::cfunc_MATH_lerp(lua_State* const luaContext)
{
  return cfunc_MATH_lerpL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004D20B0 (FUN_004D20B0, cfunc_MATH_lerpL)
 *
 * What it does:
 * Implements `MATH_Lerp` Lua overloads:
 * `(s, a, b)` and `(s, sMin, sMax, a, b)`.
 */
int moho::cfunc_MATH_lerpL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 3 || argumentCount > 5) {
    LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kMathLerpHelpText, 3, 5,
                             argumentCount);
  }

  const int resolvedArgumentCount = lua_gettop(state->m_state);
  if (resolvedArgumentCount == 3) {
    LuaPlus::LuaStackObject upperBoundArg(state, 3);
    if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&upperBoundArg, "number");
    }
    const float upperBound = static_cast<float>(lua_tonumber(state->m_state, 3));

    LuaPlus::LuaStackObject lowerBoundArg(state, 2);
    if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&lowerBoundArg, "number");
    }
    const float lowerBound = static_cast<float>(lua_tonumber(state->m_state, 2));

    LuaPlus::LuaStackObject interpolationArg(state, 1);
    if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&interpolationArg, "number");
    }
    const float interpolation = static_cast<float>(lua_tonumber(state->m_state, 1));

    const float result = lowerBound + (upperBound - lowerBound) * interpolation;
    lua_pushnumber(state->m_state, result);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  if (resolvedArgumentCount == 5) {
    LuaPlus::LuaStackObject upperBoundArg(state, 5);
    const float upperBound = static_cast<float>(upperBoundArg.ToNumber());

    LuaPlus::LuaStackObject lowerBoundArg(state, 4);
    const float lowerBound = static_cast<float>(lowerBoundArg.ToNumber());

    LuaPlus::LuaStackObject maximumInterpolationArg(state, 3);
    LuaPlus::LuaStackObject minimumInterpolationArg(state, 2);
    LuaPlus::LuaStackObject interpolationArg(state, 1);

    const float interpolation = static_cast<float>(interpolationArg.ToNumber());
    const float minimumInterpolation = static_cast<float>(minimumInterpolationArg.ToNumber());
    const float normalizedNumerator = interpolation - minimumInterpolation;
    const float normalizedDenominator =
      static_cast<float>(maximumInterpolationArg.ToNumber()) - minimumInterpolation;

    const float result =
      lowerBound + (upperBound - lowerBound) * (normalizedNumerator / normalizedDenominator);
    lua_pushnumber(state->m_state, result);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  lua_pushnil(state->m_state);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x004D2050 (FUN_004D2050, func_MATH_Lerp_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `MATH_Lerp`.
 */
moho::CScrLuaInitForm* moho::func_MATH_Lerp_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "MATH_Lerp",
    &moho::cfunc_MATH_lerp,
    nullptr,
    "<global>",
    kMathLerpHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC65B0 (FUN_00BC65B0, register_MATH_Lerp_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_MATH_Lerp_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_MATH_Lerp_LuaFuncDef()
{
  return func_MATH_Lerp_LuaFuncDef();
}
