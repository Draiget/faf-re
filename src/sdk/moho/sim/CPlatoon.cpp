#include "moho/sim/CPlatoon.h"

#include <cstring>
#include <string>

#include "gpg/core/containers/String.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptEvent.h"

namespace moho
{
  template <>
  class CScrLuaMetatableFactory<CPlatoon> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CPlatoon>) == 0x08, "CScrLuaMetatableFactory<CPlatoon> size must be 0x08"
  );
} // namespace moho

namespace
{
  constexpr const char* kCanConsiderFormingPlatoonHelpText = "CPlatoon:CanConsiderFormingPlatoon()";

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("sim");
    return sSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }
} // namespace

namespace moho
{
  CScrLuaMetatableFactory<CPlatoon> CScrLuaMetatableFactory<CPlatoon>::sInstance{};

  CScrLuaMetatableFactory<CPlatoon>& CScrLuaMetatableFactory<CPlatoon>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CPlatoon>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x00BDAE70 (FUN_00BDAE70, register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Forwards startup registration to `func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef()
  {
    return func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();
  }

  /**
   * Address: 0x0072CC00 (FUN_0072CC00, cfunc_CPlatoonCanConsiderFormingPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanConsiderFormingPlatoonL`.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCanConsiderFormingPlatoonL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072CC80 (FUN_0072CC80, cfunc_CPlatoonCanConsiderFormingPlatoonL)
   *
   * What it does:
   * Validates one `CPlatoon` method call and returns whether arg#3 matches
   * the first element of arg#2 case-insensitively.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoonL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kCanConsiderFormingPlatoonHelpText,
        3,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    (void)SCR_FromLua_CPlatoon(platoonObject, state);

    LuaPlus::LuaObject compareTable(LuaPlus::LuaStackObject(state, 2));
    const char* inputString = lua_tostring(state->m_state, 3);
    if (!inputString) {
      LuaPlus::LuaStackObject typeErrorArg(state, 3);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }

    std::string inputText(inputString ? inputString : "");
    LuaPlus::LuaObject compareObject = compareTable[1];
    const char* compareString = compareObject.GetString();

    const int compareResult = _memicmp(inputText.c_str(), compareString, inputText.size());
    lua_pushboolean(state->m_state, compareResult ? 0 : 1);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072CC20 (FUN_0072CC20, func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanConsiderFormingPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CanConsiderFormingPlatoon",
      &cfunc_CPlatoonCanConsiderFormingPlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCanConsiderFormingPlatoonHelpText
    );
    return &binder;
  }
} // namespace moho

namespace
{
  struct CPlatoonLuaBindingBootstrap
  {
    CPlatoonLuaBindingBootstrap()
    {
      (void)moho::register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();
    }
  };

  [[maybe_unused]] CPlatoonLuaBindingBootstrap gCPlatoonLuaBindingBootstrap;
} // namespace
