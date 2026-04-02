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
