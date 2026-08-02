#include "moho/lua/SCR_Trace.h"

#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"

namespace
{
  constexpr const char* kTraceHelpText = "Trace(true) -- turns on debug tracing\nTrace(false) -- turns it off again";

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    // Every file that wants this set must resolve the one that already
    // exists. Declaring a fresh static here creates a second set with the
    // same name, and SCR_FindLuaInitFormSet returns only the first - so
    // half the binders never get run.
    if (moho::CScrLuaInitFormSet* const existing = moho::SCR_FindLuaInitFormSet("core"); existing != nullptr) {
      return *existing;
    }

    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
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
  return cfunc_TraceL(moho::SCR_ResolveBindingState(luaContext));
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

namespace
{
  /**
   * Drives this file's Lua binder registrations.
   *
   * In the shipped binary each `register_*_LuaFuncDef` thunk is a
   * compiler-generated dynamic initializer, so the CRT's static-init array
   * calls every one of them before `main`. Nothing in this tree reproduces
   * that array, so a recovered thunk that no source line names is simply
   * never run - the binder is never constructed, the form never joins its
   * init-form set, and the global it publishes is missing at runtime with no
   * diagnostic beyond FAF's own "access to nonexistent global variable".
   *
   * This object is that call, and it is also the source-level invocation
   * that keeps the thunks out of the linker's dead-strip.
   */
  struct SCRTraceLuaBinderBootstrap
  {
    SCRTraceLuaBinderBootstrap()
    {
      (void)::moho::register_Trace_LuaFuncDef();
    }
  };

  const SCRTraceLuaBinderBootstrap gSCRTraceLuaBinderBootstrap{};
} // namespace
