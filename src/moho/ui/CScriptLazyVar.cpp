#include "moho/ui/UiPrivate.h"

extern "C" const LuaPlus::TObject* luaH_getnum(Table* t, int key);

/**
 * Address: 0x007836E0 (FUN_007836E0, ??0CScriptLazyVar_float@Moho@@QAE@@Z)
 *
 * What it does:
 * Imports `/lua/lazyvar.lua` and initializes this lazy-var from
 * `lazyvar.Create(0.0)`.
 */
moho::CScriptLazyVar_float::CScriptLazyVar_float(
  LuaPlus::LuaState* const state
)
{
  LuaPlus::LuaObject& lazyVarObject = *this;

  if (state == nullptr || state->m_state == nullptr) {
    return;
  }

  LuaPlus::LuaObject lazyVarModule = SCR_Import(state, "/lua/lazyvar.lua");
  LuaPlus::LuaObject createFn = lazyVarModule.GetByName("Create");

  lua_State* const rawState = state->m_state;
  const int savedTop = lua_gettop(rawState);

  createFn.PushStack(state);
  lua_pushnumber(rawState, 0.0f);

  if (LuaCallProtected(rawState, 1, 1) != 0) {
    LuaPlus::LuaStackObject errorStack(state, -1);
    const char* errorText = errorStack.GetString();
    if (errorText == nullptr) {
      errorStack.TypeError("string");
      errorText = "<non-string>";
    }
    gpg::Warnf("Error in lazyvar.Create(): %s", errorText);
  } else {
    LuaPlus::LuaObject created(state, -1);
    lazyVarObject = created;
  }

  lua_settop(rawState, savedTop);
}

/**
 * Address: 0x00783840 (FUN_00783840, Moho::CScriptLazyVar_float::GetValue)
 *
 * What it does:
 * Resolves lazy-var value lane `1`, evaluating the lazy callback when the
 * lane is nil and coercing error/non-number paths back to `0.0`.
 */
float moho::CScriptLazyVar_float::GetValue(
  const CScriptLazyVar_float* const value
) noexcept
{
  if (value == nullptr) {
    return 0.0f;
  }

  const LuaPlus::LuaObject& lazyVarObject = *value;
  if (lazyVarObject.m_state == nullptr) {
    return 0.0f;
  }

  // Engine change: what GetByIndex finds first when slot 1 holds a number, without linking a LuaObject
  // into the state's used list and out again. Each UI control reads several of these each frame.
  if (lazyVarObject.m_object.tt == LUA_TTABLE) {
    const LuaPlus::TObject* const slot = luaH_getnum(static_cast<Table*>(lazyVarObject.m_object.value.p), 1);
    if (slot->tt == LUA_TNUMBER) {
      return static_cast<float>(slot->value.n);
    }
  }

  LuaPlus::LuaObject resolvedValue = lazyVarObject.GetByIndex(1);
  if (resolvedValue.IsNil()) {
    LuaPlus::LuaState* const activeState = lazyVarObject.GetActiveState();
    if (activeState == nullptr || activeState->m_state == nullptr) {
      return 0.0f;
    }

    lua_State* const rawState = activeState->m_state;
    const int savedTop = lua_gettop(rawState);

    lazyVarObject.PushStack(activeState);
    if (LuaCallProtected(rawState, 0, 1) != 0) {
      LuaPlus::LuaStackObject errorStack(activeState, -1);
      const char* errorText = errorStack.GetString();
      if (errorText == nullptr) {
        errorStack.TypeError("string");
        errorText = "<non-string>";
      }
      gpg::Warnf("Evaluating LazyVar failed: %s", errorText);
      const_cast<LuaPlus::LuaObject&>(lazyVarObject).SetNumber(1, 0.0f);
      lua_settop(rawState, savedTop);
      return 0.0f;
    }

    resolvedValue = LuaPlus::LuaObject(LuaPlus::LuaStackObject(activeState, -1));
    lua_settop(rawState, savedTop);
  }

  if (resolvedValue.IsNumber()) {
    return static_cast<float>(resolvedValue.GetNumber());
  }

  const_cast<LuaPlus::LuaObject&>(lazyVarObject).SetNumber(1, 0.0f);
  gpg::Warnf("LazyVar has non-number value.");
  return 0.0f;
}

/**
 * Address: 0x007839E0 (FUN_007839E0, Moho::CScriptLazyVar_float::SetValue)
 *
 * What it does:
 * Calls the Lua-side `SetValue` method on this lazy-var with `next`.
 */
void moho::CScriptLazyVar_float::SetValue(
  CScriptLazyVar_float* const value,
  const float next
) noexcept
{
  if (value == nullptr) {
    return;
  }

  LuaPlus::LuaObject& lazyVarObject = *value;
  LuaPlus::LuaState* const activeState = lazyVarObject.GetActiveState();
  if (activeState == nullptr || activeState->m_state == nullptr) {
    return;
  }

  lua_State* const rawState = activeState->m_state;
  const int savedTop = lua_gettop(rawState);

  lazyVarObject.PushStack(activeState);
  lua_pushstring(rawState, "SetValue");
  lua_gettable(rawState, -2);
  lazyVarObject.PushStack(activeState);
  lua_pushnumber(rawState, next);

  if (LuaCallProtected(rawState, 2, 0) != 0) {
    LuaPlus::LuaStackObject errorStack(activeState, -1);
    const char* errorText = errorStack.GetString();
    if (errorText == nullptr) {
      errorStack.TypeError("string");
      errorText = "<non-string>";
    }
    gpg::Warnf("Setting LazyVar value failed: %s", errorText);
  }

  lua_settop(rawState, savedTop);
}
