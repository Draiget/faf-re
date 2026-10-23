#pragma once

struct lua_State;

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class CScrLuaInitForm;

  /**
   * Address: 0x0050D3B0 (FUN_0050D3B0, cfunc_OrientFromDir)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_OrientFromDirL`.
   */
  int cfunc_OrientFromDir(lua_State* luaContext);

  /**
   * Address: 0x0050D430 (FUN_0050D430, cfunc_OrientFromDirL)
   *
   * What it does:
   * Implements global `OrientFromDir(vector)` and returns a quaternion Lua
   * object.
   */
  int cfunc_OrientFromDirL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0050D3D0 (FUN_0050D3D0, func_OrientFromDir_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `OrientFromDir`.
   */
  CScrLuaInitForm* func_OrientFromDir_LuaFuncDef();

  /**
   * Address: 0x00BC7F10 (FUN_00BC7F10, register_OrientFromDir_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_OrientFromDir_LuaFuncDef`.
   */
  CScrLuaInitForm* register_OrientFromDir_LuaFuncDef();

  /**
   * Address: 0x0050D510 (FUN_0050D510, cfunc_EulerToQuaternion)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_EulerToQuaternionL`.
   */
  int cfunc_EulerToQuaternion(lua_State* luaContext);

  /**
   * Address: 0x0050D590 (FUN_0050D590, cfunc_EulerToQuaternionL)
   *
   * What it does:
   * Implements global `EulerToQuaternion(float roll, float pitch, float yaw)`
   * and returns a quaternion Lua object.
   */
  int cfunc_EulerToQuaternionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0050D530 (FUN_0050D530, func_EulerToQuaternion_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EulerToQuaternion`.
   */
  CScrLuaInitForm* func_EulerToQuaternion_LuaFuncDef();

  /**
   * Address: 0x00BC7F20 (FUN_00BC7F20, register_EulerToQuaternion_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_EulerToQuaternion_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EulerToQuaternion_LuaFuncDef();

  /**
   * Address: 0x0050D730 (FUN_0050D730, cfunc_MinLerp)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_MinLerpL`.
   */
  int cfunc_MinLerp(lua_State* luaContext);

  /**
   * Address: 0x0050D7B0 (FUN_0050D7B0, cfunc_MinLerpL)
   *
   * What it does:
   * Implements global `MinLerp(float alpha, quaternion L, quaternion R)` and
   * returns the shortest-path normalized lerp of the input quaternions.
   */
  int cfunc_MinLerpL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0050D750 (FUN_0050D750, func_MinLerp_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `MinLerp`.
   */
  CScrLuaInitForm* func_MinLerp_LuaFuncDef();

  /**
   * Address: 0x00BC7F30 (FUN_00BC7F30, register_MinLerp_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_MinLerp_LuaFuncDef`.
   */
  CScrLuaInitForm* register_MinLerp_LuaFuncDef();

  /**
   * Address: 0x0050D950 (FUN_0050D950, cfunc_MinSlerp)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_MinSlerpL`.
   */
  int cfunc_MinSlerp(lua_State* luaContext);

  /**
   * Address: 0x0050D9D0 (FUN_0050D9D0, cfunc_MinSlerpL)
   *
   * What it does:
   * Implements global `MinSlerp(float alpha, quaternion L, quaternion R)` and
   * returns the shortest-path spherical interpolation of the input quaternions.
   */
  int cfunc_MinSlerpL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0050D970 (FUN_0050D970, func_MinSlerp_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `MinSlerp`.
   */
  CScrLuaInitForm* func_MinSlerp_LuaFuncDef();

  /**
   * Address: 0x00BC7F40 (FUN_00BC7F40, register_MinSlerp_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_MinSlerp_LuaFuncDef`.
   */
  CScrLuaInitForm* register_MinSlerp_LuaFuncDef();

  /**
   * Address: 0x004D0140 (FUN_004D0140, cfunc_Vector)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_VectorL`.
   */
  int cfunc_Vector(lua_State* luaContext);

  /**
   * Address: 0x004D01C0 (FUN_004D01C0, cfunc_VectorL)
   *
   * What it does:
   * Implements global `Vector(x, y, z)` and returns a Vector3f Lua object.
   */
  int cfunc_VectorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D0160 (FUN_004D0160, func_Vector_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `Vector`.
   */
  CScrLuaInitForm* func_Vector_LuaFuncDef();

  /**
   * Address: 0x00BC64E0 (FUN_00BC64E0, register_Vector_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_Vector_LuaFuncDef`.
   */
  CScrLuaInitForm* register_Vector_LuaFuncDef();

  /**
   * Address: 0x004CFE00 (FUN_004CFE00, cfunc_Vector2)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_Vector2L`.
   */
  int cfunc_Vector2(lua_State* luaContext);

  /**
   * Address: 0x004CFE80 (FUN_004CFE80, cfunc_Vector2L)
   *
   * What it does:
   * Implements global `Vector2(x, y)` and returns a Vector2f Lua object.
   */
  int cfunc_Vector2L(LuaPlus::LuaState* state);

  /**
   * Address: 0x004CFE20 (FUN_004CFE20, func_Vector2_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `Vector2`.
   */
  CScrLuaInitForm* func_Vector2_LuaFuncDef();

  /**
   * Address: 0x00BC64D0 (FUN_00BC64D0, register_Vector2_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_Vector2_LuaFuncDef`.
   */
  CScrLuaInitForm* register_Vector2_LuaFuncDef();

  /**
   * Address: 0x004D0600 (FUN_004D0600, cfunc_PointVector)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_PointVectorL`.
   */
  int cfunc_PointVector(lua_State* luaContext);

  /**
   * Address: 0x004D0680 (FUN_004D0680, cfunc_PointVectorL)
   *
   * What it does:
   * Implements global `PointVector(px, py, pz, vx, vy, vz)` and returns
   * one `SPointVector` Lua object.
   */
  int cfunc_PointVectorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D0620 (FUN_004D0620, func_PointVector_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `PointVector`.
   */
  CScrLuaInitForm* func_PointVector_LuaFuncDef();

  /**
   * Address: 0x00BC64F0 (FUN_00BC64F0, register_PointVector_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_PointVector_LuaFuncDef`.
   */
  CScrLuaInitForm* register_PointVector_LuaFuncDef();

  /**
   * Address: 0x004D0C70 (FUN_004D0C70, cfunc_Rect)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_RectL`.
   */
  int cfunc_Rect(lua_State* luaContext);

  /**
   * Address: 0x004D0CF0 (FUN_004D0CF0, cfunc_RectL)
   *
   * What it does:
   * Implements global `Rect(x0, y0, x1, y1)` and returns a Rect2f Lua table.
   */
  int cfunc_RectL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D0C90 (FUN_004D0C90, func_Rect_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `Rect`.
   */
  CScrLuaInitForm* func_Rect_LuaFuncDef();

  /**
   * Address: 0x00BC6500 (FUN_00BC6500, register_Rect_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_Rect_LuaFuncDef`.
   */
  CScrLuaInitForm* register_Rect_LuaFuncDef();

  /**
   * Address: 0x004D0EB0 (FUN_004D0EB0, cfunc_VDist3)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_VDist3L`.
   */
  int cfunc_VDist3(lua_State* luaContext);

  /**
   * Address: 0x004D0F30 (FUN_004D0F30, cfunc_VDist3L)
   *
   * What it does:
   * Validates two `Vector3f` Lua arguments and returns Euclidean 3D distance.
   */
  int cfunc_VDist3L(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D0ED0 (FUN_004D0ED0, func_VDist3_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `VDist3`.
   */
  CScrLuaInitForm* func_VDist3_LuaFuncDef();

  /**
   * Address: 0x00BC6510 (FUN_00BC6510, register_VDist3_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_VDist3_LuaFuncDef`.
   */
  CScrLuaInitForm* register_VDist3_LuaFuncDef();

  /**
   * Address: 0x004D1070 (FUN_004D1070, cfunc_VDist3Sq)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_VDist3SqL`.
   */
  int cfunc_VDist3Sq(lua_State* luaContext);

  /**
   * Address: 0x004D10F0 (FUN_004D10F0, cfunc_VDist3SqL)
   *
   * What it does:
   * Validates two `Vector3f` Lua arguments and returns squared 3D distance.
   */
  int cfunc_VDist3SqL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D1090 (FUN_004D1090, func_VDist3Sq_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `VDist3Sq`.
   */
  CScrLuaInitForm* func_VDist3Sq_LuaFuncDef();

  /**
   * Address: 0x00BC6520 (FUN_00BC6520, register_VDist3Sq_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_VDist3Sq_LuaFuncDef`.
   */
  CScrLuaInitForm* register_VDist3Sq_LuaFuncDef();

  /**
   * Address: 0x004D1230 (FUN_004D1230, cfunc_VDist2)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_VDist2L`.
   */
  int cfunc_VDist2(lua_State* luaContext);

  /**
   * Address: 0x004D12B0 (FUN_004D12B0, cfunc_VDist2L)
   *
   * What it does:
   * Validates and computes Euclidean distance between two 2D points:
   * `(x1, y1, x2, y2) -> number`.
   */
  int cfunc_VDist2L(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D1250 (FUN_004D1250, func_VDist2_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `VDist2`.
   */
  CScrLuaInitForm* func_VDist2_LuaFuncDef();

  /**
   * Address: 0x00BC6530 (FUN_00BC6530, register_VDist2_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_VDist2_LuaFuncDef`.
   */
  CScrLuaInitForm* register_VDist2_LuaFuncDef();

  /**
   * Address: 0x004D1440 (FUN_004D1440, cfunc_VDist2Sq)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_VDist2SqL`.
   */
  int cfunc_VDist2Sq(lua_State* luaContext);

  /**
   * Address: 0x004D14C0 (FUN_004D14C0, cfunc_VDist2SqL)
   *
   * What it does:
   * Validates `(x1, y1, x2, y2)` numeric arguments and returns squared 2D
   * distance without square-root reduction.
   */
  int cfunc_VDist2SqL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D1460 (FUN_004D1460, func_VDist2Sq_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `VDist2Sq`.
   */
  CScrLuaInitForm* func_VDist2Sq_LuaFuncDef();

  /**
   * Address: 0x00BC6540 (FUN_00BC6540, register_VDist2Sq_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_VDist2Sq_LuaFuncDef`.
   */
  CScrLuaInitForm* register_VDist2Sq_LuaFuncDef();

  /**
   * Address: 0x004D1650 (FUN_004D1650, cfunc_VDot)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_VDotL`.
   */
  int cfunc_VDot(lua_State* luaContext);

  /**
   * Address: 0x004D16D0 (FUN_004D16D0, cfunc_VDotL)
   *
   * What it does:
   * Validates two `Vector3f` Lua arguments and returns their dot product.
   */
  int cfunc_VDotL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D1670 (FUN_004D1670, func_VDot_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `VDot`.
   */
  CScrLuaInitForm* func_VDot_LuaFuncDef();

  /**
   * Address: 0x00BC6550 (FUN_00BC6550, register_VDot_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_VDot_LuaFuncDef`.
   */
  CScrLuaInitForm* register_VDot_LuaFuncDef();

  /**
   * Address: 0x004D17E0 (FUN_004D17E0, cfunc_VDiff)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_VDiffL`.
   */
  int cfunc_VDiff(lua_State* luaContext);

  /**
   * Address: 0x004D1860 (FUN_004D1860, cfunc_VDiffL)
   *
   * What it does:
   * Validates two `Vector3f` Lua arguments and returns their difference.
   */
  int cfunc_VDiffL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D1800 (FUN_004D1800, func_VDiff_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `VDiff`.
   */
  CScrLuaInitForm* func_VDiff_LuaFuncDef();

  /**
   * Address: 0x00BC6560 (FUN_00BC6560, register_VDiff_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_VDiff_LuaFuncDef`.
   */
  CScrLuaInitForm* register_VDiff_LuaFuncDef();

  /**
   * Address: 0x004D19C0 (FUN_004D19C0, cfunc_VAdd)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_VAddL`.
   */
  int cfunc_VAdd(lua_State* luaContext);

  /**
   * Address: 0x004D1A40 (FUN_004D1A40, cfunc_VAddL)
   *
   * What it does:
   * Validates two `Vector3f` Lua arguments and returns their sum.
   */
  int cfunc_VAddL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D19E0 (FUN_004D19E0, func_VAdd_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `VAdd`.
   */
  CScrLuaInitForm* func_VAdd_LuaFuncDef();

  /**
   * Address: 0x00BC6570 (FUN_00BC6570, register_VAdd_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_VAdd_LuaFuncDef`.
   */
  CScrLuaInitForm* register_VAdd_LuaFuncDef();

  /**
   * Address: 0x004D1BA0 (FUN_004D1BA0, cfunc_VMult)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_VMultL`.
   */
  int cfunc_VMult(lua_State* luaContext);

  /**
   * Address: 0x004D1C20 (FUN_004D1C20, cfunc_VMultL)
   *
   * What it does:
   * Multiplies one `Vector3f` by one scalar and returns the resulting vector.
   */
  int cfunc_VMultL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D1BC0 (FUN_004D1BC0, func_VMult_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `VMult`.
   */
  CScrLuaInitForm* func_VMult_LuaFuncDef();

  /**
   * Address: 0x00BC6580 (FUN_00BC6580, register_VMult_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_VMult_LuaFuncDef`.
   */
  CScrLuaInitForm* register_VMult_LuaFuncDef();

  /**
   * Address: 0x004D1D70 (FUN_004D1D70, cfunc_VPerpDot)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_VPerpDotL`.
   */
  int cfunc_VPerpDot(lua_State* luaContext);

  /**
   * Address: 0x004D1DF0 (FUN_004D1DF0, cfunc_VPerpDotL)
   *
   * What it does:
   * Computes the 2D perpendicular-dot lane from two vectors:
   * `x1 * z2 - x2 * z1`.
   */
  int cfunc_VPerpDotL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D1D90 (FUN_004D1D90, func_VPerpDot_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `VPerpDot`.
   */
  CScrLuaInitForm* func_VPerpDot_LuaFuncDef();

  /**
   * Address: 0x00BC6590 (FUN_00BC6590, register_VPerpDot_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_VPerpDot_LuaFuncDef`.
   */
  CScrLuaInitForm* register_VPerpDot_LuaFuncDef();

  /**
   * Address: 0x004D1F10 (FUN_004D1F10, cfunc_MATH_IRound)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_MATH_IRoundL`.
   */
  int cfunc_MATH_IRound(lua_State* luaContext);

  /**
   * Address: 0x004D1F90 (FUN_004D1F90, cfunc_MATH_IRoundL)
   *
   * What it does:
   * Converts one numeric Lua argument to an integer lane and returns it as a
   * Lua number.
   */
  int cfunc_MATH_IRoundL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D1F30 (FUN_004D1F30, func_MATH_IRound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `MATH_IRound`.
   */
  CScrLuaInitForm* func_MATH_IRound_LuaFuncDef();

  /**
   * Address: 0x00BC65A0 (FUN_00BC65A0, register_MATH_IRound_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_MATH_IRound_LuaFuncDef`.
   */
  CScrLuaInitForm* register_MATH_IRound_LuaFuncDef();

  /**
   * Address: 0x004D2030 (FUN_004D2030, cfunc_MATH_lerp)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_MATH_lerpL`.
   */
  int cfunc_MATH_lerp(lua_State* luaContext);

  /**
   * Address: 0x004D20B0 (FUN_004D20B0, cfunc_MATH_lerpL)
   *
   * What it does:
   * Implements `MATH_Lerp` Lua overloads:
   * `(s, a, b)` and `(s, sMin, sMax, a, b)`.
   */
  int cfunc_MATH_lerpL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D2050 (FUN_004D2050, func_MATH_Lerp_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `MATH_Lerp`.
   */
  CScrLuaInitForm* func_MATH_Lerp_LuaFuncDef();

  /**
   * Address: 0x00BC65B0 (FUN_00BC65B0, register_MATH_Lerp_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_MATH_Lerp_LuaFuncDef`.
   */
  CScrLuaInitForm* register_MATH_Lerp_LuaFuncDef();
} // namespace moho
