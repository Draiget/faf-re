#include "moho/lua/SCR_Trace.h"

#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"

namespace
{
  constexpr const char* kTraceHelpText = "Trace(true) -- turns on debug tracing\nTrace(false) -- turns it off again";

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
 * Address: 0x004B41E0 (FUN_004B41E0, cfunc_Trace)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_TraceL`.
 */
int moho::cfunc_Trace(lua_State* const luaContext)
{
  return cfunc_TraceL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004B4260 (FUN_004B4260, cfunc_TraceL)
 *
 * What it does:
 * Validates one boolean argument for the `Trace` Lua API and returns no
 * Lua values.
 */
int moho::cfunc_TraceL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kTraceHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaStackObject traceToggle(state, 1);
  (void)traceToggle.GetBoolean();
  return 0;
}

/**
 * Address: 0x004B4200 (FUN_004B4200, func_Trace_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `Trace`.
 */
moho::CScrLuaInitForm* moho::func_Trace_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "Trace",
    &moho::cfunc_Trace,
    nullptr,
    "<global>",
    kTraceHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC5D50 (FUN_00BC5D50, register_Trace_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_Trace_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_Trace_LuaFuncDef()
{
  return func_Trace_LuaFuncDef();
}

