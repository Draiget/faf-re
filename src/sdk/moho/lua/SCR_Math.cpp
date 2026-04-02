#include "moho/lua/SCR_Math.h"

#include <cmath>

#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/SCR_ToLua.h"

namespace
{
  constexpr const char* kRectHelpText = "Create a 2d Rectangle (x0,y0,x1,y1)";
  constexpr const char* kVDist2HelpText = "Distance between two 2d points (x1,y1,x2,y2)";
  constexpr const char* kMathLerpHelpText =
    "MATH_Lerp(s, a, b) or MATH_Lerp(s, sMin, sMax, a, b) -> number -- linear interpolation from a (at s=0 or "
    "s=sMin) to b (at s=1 or s=sMax)";

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }
} // namespace

/**
 * Address: 0x004D0C70 (FUN_004D0C70, cfunc_Rect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_RectL`.
 */
int moho::cfunc_Rect(lua_State* const luaContext)
{
  return cfunc_RectL(ResolveBindingState(luaContext));
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
 * Address: 0x004D1230 (FUN_004D1230, cfunc_VDist2)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_VDist2L`.
 */
int moho::cfunc_VDist2(lua_State* const luaContext)
{
  return cfunc_VDist2L(ResolveBindingState(luaContext));
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
 * Address: 0x004D2030 (FUN_004D2030, cfunc_MATH_lerp)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_MATH_lerpL`.
 */
int moho::cfunc_MATH_lerp(lua_State* const luaContext)
{
  return cfunc_MATH_lerpL(ResolveBindingState(luaContext));
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
