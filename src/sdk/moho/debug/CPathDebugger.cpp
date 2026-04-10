#include "moho/debug/CPathDebugger.h"

#include "moho/lua/CScrLuaBinder.h"
#include "moho/script/CScriptEvent.h"
#include "moho/debug/RDebugOverlayReflectionHelpers.h"

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kCreatePathDebuggerName = "_c_CreatePathDebugger";
  constexpr const char* kCreatePathDebuggerHelpText = "_c_CreatePathDebugger(luaobj,spec)";
  constexpr const char* kCPathDebuggerLuaClassName = "CPathDebugger";
  constexpr const char* kCPathDebuggerDestroyName = "Destroy";
  constexpr const char* kCPathDebuggerDestroyHelpText = "Destroy the path debugger";

  [[nodiscard]] moho::CScrLuaInitFormSet* FindUserLuaInitSet() noexcept
  {
    return moho::SCR_FindLuaInitFormSet("User");
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = FindUserLuaInitSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }
} // namespace

namespace moho
{
  CScrLuaMetatableFactory<CPathDebugger> CScrLuaMetatableFactory<CPathDebugger>::sInstance{};
  gpg::RType* CPathDebugger::sType = nullptr;

  CScrLuaMetatableFactory<CPathDebugger>& CScrLuaMetatableFactory<CPathDebugger>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CPathDebugger>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x007B5C90 (FUN_007B5C90)
   */
  CPathDebugger::CPathDebugger(const LuaPlus::LuaObject& luaObject)
  {
    SetLuaObject(luaObject);
  }

  /**
   * Address: 0x007B5C50 (FUN_007B5C50, Moho::CPathDebugger::GetClass)
   */
  gpg::RType* CPathDebugger::GetClass() const
  {
    return debug_reflection::ResolveObjectType<CPathDebugger>(sType);
  }

  /**
   * Address: 0x007B5C70 (FUN_007B5C70, Moho::CPathDebugger::GetDerivedObjectRef)
   */
  gpg::RRef CPathDebugger::GetDerivedObjectRef()
  {
    return debug_reflection::MakeRef(this, GetClass());
  }

  /**
   * Address: 0x007B5CE0 (FUN_007B5CE0, Moho::CPathDebugger::dtr)
   */
  CPathDebugger::~CPathDebugger() = default;

  /**
   * Address: 0x007B5F90 (FUN_007B5F90, cfunc__c_CreatePathDebugger)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc__c_CreatePathDebuggerL`.
   */
  int cfunc__c_CreatePathDebugger(lua_State* const luaContext)
  {
    return cfunc__c_CreatePathDebuggerL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007B5FB0 (FUN_007B5FB0, func__c_CreatePathDebugger_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder metadata for `_c_CreatePathDebugger`.
   */
  CScrLuaInitForm* func__c_CreatePathDebugger_LuaFuncDef()
  {
    static CCreatePathDebugger_LuaFuncDef binder(
      UserLuaInitSet(),
      kCreatePathDebuggerName,
      &cfunc__c_CreatePathDebugger,
      nullptr,
      "<global>",
      kCreatePathDebuggerHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007B6010 (FUN_007B6010, cfunc__c_CreatePathDebuggerL)
   *
   * What it does:
   * Validates `(luaobj, spec)` argument shape, creates one `CPathDebugger`
   * script object from the first argument, and pushes its Lua object.
   */
  int cfunc__c_CreatePathDebuggerL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreatePathDebuggerHelpText, 2, argumentCount);
    }

    CPathDebugger* pathDebugger = nullptr;
    {
      const LuaPlus::LuaObject luaObjectArgument(LuaPlus::LuaStackObject(state, 1));
      pathDebugger = new CPathDebugger(luaObjectArgument);
    }

    pathDebugger->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x007B5E60 (FUN_007B5E60, cfunc_CPathDebuggerDestroy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CPathDebuggerDestroyL`.
   */
  int cfunc_CPathDebuggerDestroy(lua_State* const luaContext)
  {
    return cfunc_CPathDebuggerDestroyL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007B5E80 (FUN_007B5E80, func_CPathDebuggerDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CPathDebugger:Destroy`.
   */
  CScrLuaInitForm* func_CPathDebuggerDestroy_LuaFuncDef()
  {
    static CPathDebuggerDestroy_LuaFuncDef binder(
      UserLuaInitSet(),
      kCPathDebuggerDestroyName,
      &cfunc_CPathDebuggerDestroy,
      &CScrLuaMetatableFactory<CPathDebugger>::Instance(),
      kCPathDebuggerLuaClassName,
      kCPathDebuggerDestroyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007B5EE0 (FUN_007B5EE0, cfunc_CPathDebuggerDestroyL)
   *
   * What it does:
   * Validates one `CPathDebugger` argument from Lua, resolves object ownership,
   * and deletes the script object when it is still alive.
   */
  int cfunc_CPathDebuggerDestroyL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCPathDebuggerDestroyHelpText, 1, argumentCount);
    }

    CPathDebugger* pathDebugger = nullptr;
    {
      const LuaPlus::LuaObject pathDebuggerObject(LuaPlus::LuaStackObject(state, 1));
      pathDebugger = SCR_FromLua_CPathDebugger(pathDebuggerObject, state);
    }

    if (pathDebugger != nullptr) {
      delete pathDebugger;
    }

    return 0;
  }
} // namespace moho
