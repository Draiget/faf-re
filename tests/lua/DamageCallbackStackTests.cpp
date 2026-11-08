#include <cstring>
#include <stdexcept>
#include <string>
#include <gtest/gtest.h>

#include "lua/LuaObject.h"
#include "lua/LuaPrimitives.h"
#include "moho/entity/Entity.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptObject.h"

namespace
{
  // Only supplies an object identity. Callback lookup, argument setup, the Lua
  // parser/VM, error unwind and the RunScript wrappers are production code.
  class CallbackObject : public moho::CScriptObject
  {
  public:
    CallbackObject() = default;
    gpg::RType* GetClass() const override { return moho::CScriptObject::StaticGetClass(); }
    gpg::RRef GetDerivedObjectRef() override { return {this, GetClass()}; }
    fa::string GetErrorDescription() override { return "damage callback test"; }
  };

  class DamageCallbackStack : public ::testing::Test
  {
  protected:
    LuaPlus::LuaState state{LuaPlus::LuaState::LIB_BASE};
    CallbackObject object;
    moho::WeakPtr<moho::Entity> source;

    void Run(const char* code)
    {
      lua_State* const L = state.GetCState();
      const int top = lua_gettop(L);
      ASSERT_EQ(luaL_loadbuffer(L, code, std::strlen(code), "=damage-stack-test"), 0)
        << (lua_tostring(L, -1) ? lua_tostring(L, -1) : "load error");
      ASSERT_EQ(LuaCallProtected(L, 0, 0), 0)
        << (lua_tostring(L, -1) ? lua_tostring(L, -1) : "call error");
      ASSERT_EQ(lua_gettop(L), top);
    }

    void SetUp() override
    {
      Run("callbacks = { damageCalls = 0, absorptionCalls = 0, "
          "OnDamage = function(self) self.damageCalls = self.damageCalls + 1; error('damage failed') end, "
          "OnGetDamageAbsorption = function(self) self.absorptionCalls = self.absorptionCalls + 1; error('absorption failed') end }");
      object.mLuaObj = state.GetGlobal("callbacks");
    }

    void CheckSentinel()
    {
      lua_State* const L = state.GetCState();
      EXPECT_EQ(lua_gettop(L), 1);
      EXPECT_EQ(lua_type(L, 1), LUA_TNUMBER);
      EXPECT_FLOAT_EQ(lua_tonumber(L, 1), 314.0f);
    }
  };

  TEST_F(DamageCallbackStack, DamageErrorsRestoreExistingCallerStack)
  {
    lua_pushnumber(state.GetCState(), 314.0f);
    LuaPlus::LuaObject payload = state.GetGlobal("callbacks");
    for (int i = 0; i < 64; ++i) {
      object.RunScriptEntityOnDamage(source, 7.0f, payload, "Normal");
      CheckSentinel();
    }
    Run("assert(callbacks.damageCalls == 64)");
  }

  TEST_F(DamageCallbackStack, AbsorptionErrorsRestoreExistingCallerStack)
  {
    lua_pushnumber(state.GetCState(), 314.0f);
    for (int i = 0; i < 64; ++i) {
      EXPECT_FLOAT_EQ(object.RunScriptOnGetDamageAbsorption(source, 7.0f, "Normal"), 0.0f);
      CheckSentinel();
    }
    Run("assert(callbacks.absorptionCalls == 64)");
  }

  TEST_F(DamageCallbackStack, SuccessfulCallsAfterCaughtErrorsKeepArgumentsAndResults)
  {
    LuaPlus::LuaObject payload = state.GetGlobal("callbacks");
    lua_pushnumber(state.GetCState(), 314.0f);
    object.RunScriptEntityOnDamage(source, 7.0f, payload, "Normal");
    EXPECT_FLOAT_EQ(object.RunScriptOnGetDamageAbsorption(source, 7.0f, "Normal"), 0.0f);
    CheckSentinel();
    Run("callbacks.OnDamage = function(self, source, amount, payload, kind) "
        "assert(self == callbacks and source == nil and amount == 7 and payload == callbacks and kind == 'Normal'); "
        "self.called = true end; "
        "callbacks.OnGetDamageAbsorption = function(self, source, amount, kind) "
        "assert(self == callbacks and source == nil and amount == 7 and kind == 'Normal'); return 2.5 end");
    object.RunScriptEntityOnDamage(source, 7.0f, payload, "Normal");
    EXPECT_FLOAT_EQ(object.RunScriptOnGetDamageAbsorption(source, 7.0f, "Normal"), 2.5f);
    CheckSentinel();
    Run("assert(callbacks.called)");
  }

  int NativeBatch(lua_State* L)
  {
    auto* const object = static_cast<CallbackObject*>(lua_touserdata(L, lua_upvalueindex(1)));
    moho::WeakPtr<moho::Entity> source;
    LuaPlus::LuaObject payload = object->mLuaObj;
    for (int i = 0; i < 32; ++i) {
      object->RunScriptEntityOnDamage(source, 7.0f, payload, "Normal");
      EXPECT_FLOAT_EQ(object->RunScriptOnGetDamageAbsorption(source, 7.0f, "Normal"), 0.0f);
    }
    EXPECT_EQ(lua_gettop(L), 1) << "Caught inner errors must not replace this binding's return value";
    return 1;
  }

  TEST_F(DamageCallbackStack, RealNativeFrameReturnsOriginalArgumentAfterCaughtErrors)
  {
    lua_State* const L = state.GetCState();
    lua_pushlightuserdata(L, &object);
    lua_pushcclosure(L, NativeBatch, 1);
    lua_setglobal(L, "nativeBatch");
    Run("assert(nativeBatch(314) == 314); assert(callbacks.damageCalls == 32 and callbacks.absorptionCalls == 32)");
  }

  TEST_F(DamageCallbackStack, WrappedCoroutineRestoresItsOwnNativeFrame)
  {
    lua_State* const root = state.GetCState();
    lua_pushlightuserdata(root, &object);
    lua_pushcclosure(root, NativeBatch, 1);
    lua_setglobal(root, "nativeBatch");
    lua_pushnumber(root, 314.0f);
    LuaPlus::LuaState child(&state);
    lua_State* const coroutine = child.GetCState();
    ASSERT_NE(coroutine, root);
    const char* const code = "assert(nativeBatch(271) == 271)";
    ASSERT_EQ(luaL_loadbuffer(coroutine, code, std::strlen(code), "=coroutine-damage-stack"), 0);
    ASSERT_EQ(LuaCallProtected(coroutine, 0, 0), 0)
      << (lua_tostring(coroutine, -1) ? lua_tostring(coroutine, -1) : "call error");
    EXPECT_EQ(lua_gettop(coroutine), 0);
    CheckSentinel();
    Run("assert(callbacks.damageCalls == 32 and callbacks.absorptionCalls == 32)");
  }

  TEST_F(DamageCallbackStack, MissingCallbacksLeaveCallerStackAlone)
  {
    Run("callbacks.OnDamage = nil; callbacks.OnGetDamageAbsorption = nil");
    lua_pushnumber(state.GetCState(), 314.0f);
    LuaPlus::LuaObject payload = state.GetGlobal("callbacks");
    object.RunScriptEntityOnDamage(source, 7.0f, payload, "Normal");
    EXPECT_FLOAT_EQ(object.RunScriptOnGetDamageAbsorption(source, 7.0f, "Normal"), 0.0f);
    CheckSentinel();
  }

  TEST_F(DamageCallbackStack, PartialArgumentSetupDoesNotPolluteCallerStack)
  {
    lua_pushnumber(state.GetCState(), 314.0f);
    const LuaPlus::LuaObject unboundPayload;
    object.RunScriptEntityOnDamage(source, 7.0f, unboundPayload, "Normal");
    CheckSentinel();
    Run("assert(callbacks.damageCalls == 0)");
  }

  TEST_F(DamageCallbackStack, AbsorptionResultConversionAndStackAreUnchanged)
  {
    lua_pushnumber(state.GetCState(), 314.0f);
    Run("callbacks.OnGetDamageAbsorption = function() return nil end");
    EXPECT_FLOAT_EQ(object.RunScriptOnGetDamageAbsorption(source, 7.0f, "Normal"), 0.0f);
    CheckSentinel();
    Run("callbacks.OnGetDamageAbsorption = function() return '2.5' end");
    EXPECT_FLOAT_EQ(object.RunScriptOnGetDamageAbsorption(source, 7.0f, "Normal"), 2.5f);
    CheckSentinel();
    Run("callbacks.OnGetDamageAbsorption = function() return {} end");
    EXPECT_FLOAT_EQ(object.RunScriptOnGetDamageAbsorption(source, 7.0f, "Normal"), 0.0f);
    CheckSentinel();
  }

  TEST_F(DamageCallbackStack, NestedLuaFramesRestoreTheNativeCallerStack)
  {
    Run("local function recurse(n) if n == 0 then error('nested failure') end; "
        "return recurse(n - 1) + 1 end; "
        "callbacks.OnDamage = function(self) self.damageCalls = self.damageCalls + 1; recurse(128) end");
    lua_pushnumber(state.GetCState(), 314.0f);
    LuaPlus::LuaObject payload = state.GetGlobal("callbacks");
    object.RunScriptEntityOnDamage(source, 7.0f, payload, "Normal");
    CheckSentinel();
    Run("assert(callbacks.damageCalls == 1)");
  }

  int standardExceptionCalls = 0;

  int ThrowStandardException(lua_State*)
  {
    ++standardExceptionCalls;
    throw std::runtime_error("native callback failed");
  }

  TEST_F(DamageCallbackStack, StandardCppExceptionsUseTheVmUnwindAndRestoreTop)
  {
    lua_State* const L = state.GetCState();
    standardExceptionCalls = 0;
    lua_pushcclosure(L, ThrowStandardException, 0);
    lua_setglobal(L, "throwStandardException");
    Run("callbacks.OnDamage = throwStandardException; callbacks.OnGetDamageAbsorption = throwStandardException");
    lua_pushnumber(L, 314.0f);
    LuaPlus::LuaObject payload = state.GetGlobal("callbacks");
    object.RunScriptEntityOnDamage(source, 7.0f, payload, "Normal");
    EXPECT_FLOAT_EQ(object.RunScriptOnGetDamageAbsorption(source, 7.0f, "Normal"), 0.0f);
    CheckSentinel();
    EXPECT_EQ(standardExceptionCalls, 2);
  }
}
