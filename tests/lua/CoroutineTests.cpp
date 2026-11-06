#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <gtest/gtest.h>

#include "lua/LuaObject.h"
#include "lua/LuaPrimitives.h"
#include "lua/LuaRuntimeTypes.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/task/CTaskThread.h"

namespace moho
{
  class CLuaTask;
}

namespace
{
  void Assert(const bool condition, const char* const message, const std::string& detail = "")
  {
    EXPECT_TRUE(condition) << message << (detail.empty() ? "" : " (detail: ") << detail << (detail.empty() ? "" : ")");
  }

  int CountCoroutineThreads(lua_State* const L)
  {
    int count = 0;
    if (L != nullptr && L->l_G != nullptr) {
      for (GCObject* obj = L->l_G->rootgc1; obj != nullptr; obj = obj->gch.next) {
        ++count;
      }
    }
    return count;
  }

  std::string RunLua(LuaPlus::LuaState& state, const std::string& source)
  {
    lua_State* const L = state.GetCState();
    const int top = lua_gettop(L);
    std::string result;
    if (luaL_loadbuffer(L, source.data(), source.size(), "=test") != 0 || LuaCallProtected(L, 0, 1) != 0) {
      const char* const error = lua_tostring(L, -1);
      result = std::string("error: ") + (error != nullptr ? error : "?");
    } else {
      const char* const text = lua_tostring(L, -1);
      result = text != nullptr ? text : "ok";
    }
    lua_settop(L, top);
    return result;
  }

  class Existing_Coroutine : public ::testing::Test
  {
  protected:
    moho::CTaskStage stage;
    LuaPlus::LuaState state{LuaPlus::LuaState::LIB_BASE};

    void SetUp() override
    {
      moho::SCR_FindLuaInitFormSet("Core")->RunInits(&state);
      state.m_luaTask = reinterpret_cast<moho::CLuaTask*>(&stage);
    }

    void TearDown() override
    {
      stage.Teardown();
    }
  };

  TEST_F(Existing_Coroutine, ArgumentValidation)
  {
    const std::string res = RunLua(state, R"(
      local ok1, err1 = pcall(coroutine.create, 123)
      local ok2, err2 = pcall(coroutine.create, "string")
      local ok3, err3 = pcall(coroutine.create, print)
      local ok4, co = pcall(coroutine.create, function() end)
      if ok1 or string.find(tostring(err1), "Lua function expected", 1, true) == nil then
        return "number not rejected"
      end
      if ok2 or string.find(tostring(err2), "Lua function expected", 1, true) == nil then
        return "string not rejected"
      end
      if ok3 or string.find(tostring(err3), "Lua function expected", 1, true) == nil then
        return "cfunction not rejected"
      end
      if not ok4 or type(co) ~= "thread" then
        return "lua function not accepted"
      end
      return "ok"
    )");
    Assert(res == "ok", "coroutine.create argument validation (rejects non-functions and cfunctions, accepts lua functions)");
  }

  TEST_F(Existing_Coroutine, StatusLifecycle)
  {
    const std::string res = RunLua(state, R"(
      local insideStatus = nil
      local co
      co = coroutine.create(function()
        insideStatus = coroutine.status(co)
        coroutine.yield()
      end)

      if coroutine.status(co) ~= "suspended" then
        return "initial status not suspended"
      end

      local ok = coroutine.resume(co)
      if not ok then return "resume failed" end
      if insideStatus ~= "running" then
        return "running status expected inside, got " .. tostring(insideStatus)
      end
      if coroutine.status(co) ~= "suspended" then
        return "status after yield not suspended"
      end

      coroutine.resume(co)
      if coroutine.status(co) ~= "dead" then
        return "final status not dead"
      end

      return "ok"
    )");
    Assert(res == "ok", "coroutine.status reports suspended -> running -> suspended -> dead");
  }

  TEST_F(Existing_Coroutine, ResumeYieldValues)
  {
    const std::string res = RunLua(state, R"(
      local co = coroutine.create(function(a, b)
        local c, d = coroutine.yield(a + b, a - b)
        return c * d, c + d
      end)

      local ok1, sum, diff = coroutine.resume(co, 10, 4)
      if not ok1 or sum ~= 14 or diff ~= 6 then
        return "first resume failed: " .. tostring(sum) .. ", " .. tostring(diff)
      end

      local ok2, prod, sum2 = coroutine.resume(co, 5, 3)
      if not ok2 or prod ~= 15 or sum2 ~= 8 then
        return "second resume failed: " .. tostring(prod) .. ", " .. tostring(sum2)
      end

      local ok3, deadErr = coroutine.resume(co, 1)
      if ok3 or string.find(tostring(deadErr), "cannot resume dead coroutine", 1, true) == nil then
        return "resuming dead coroutine not rejected properly: " .. tostring(deadErr)
      end

      return "ok"
    )");
    Assert(res == "ok", "coroutine.resume / coroutine.yield argument and return value passing");
  }

  TEST_F(Existing_Coroutine, MultiStepGenerator)
  {
    const std::string res = RunLua(state, R"(
      local function range(n)
        return coroutine.wrap(function()
          for i = 1, n do
            coroutine.yield(i)
          end
        end)
      end

      local total = 0
      for val in range(5) do
        total = total + val
      end
      if total ~= 15 then
        return "generator sum expected 15, got " .. tostring(total)
      end
      return "ok"
    )");
    Assert(res == "ok", "coroutine.wrap works as an iterator generator");
  }

  TEST_F(Existing_Coroutine, ErrorHandling)
  {
    const std::string res = RunLua(state, R"(
      local co = coroutine.create(function()
        error("coroutine error test")
      end)

      local ok, err = coroutine.resume(co)
      if ok then
        return "expected error from resume, but got success"
      end
      if string.find(tostring(err), "coroutine error test", 1, true) == nil then
        return "wrong error message: " .. tostring(err)
      end
      if coroutine.status(co) ~= "dead" then
        return "errored coroutine not dead"
      end

      return "ok"
    )");
    Assert(res == "ok", "coroutine runtime errors propagate through resume as (false, msg) and leave thread dead");
  }

  TEST_F(Existing_Coroutine, EngineFunctions)
  {
    std::string res = RunLua(state, R"(
      local co
      co = coroutine.create(function()
        if CurrentThread() ~= co then
          return "CurrentThread mismatch"
        end
        -- As in the binary, for a thread that isn't a ForkThread: KillThread does nothing and
        -- ResumeThread warns and returns.
        local okKill, killErr = pcall(KillThread, co)
        if not okKill then
          return "KillThread raised: " .. tostring(killErr)
        end
        local okResume, resumeErr = pcall(ResumeThread, co)
        if not okResume then
          return "ResumeThread raised: " .. tostring(resumeErr)
        end
        ForkThread(function() _G.test_fork_ran = true end)
        return "ok"
      end)

      local ok, ret = coroutine.resume(co)
      if not ok then return "resume failed: " .. tostring(ret) end
      return ret
    )");
    Assert(res == "ok", "engine functions work inside a coroutine (CurrentThread, KillThread, ResumeThread, ForkThread)", res);

    stage.UserFrame();
    res = RunLua(state, "return tostring(_G.test_fork_ran)");
    Assert(res == "true", "a thread forked from inside a coroutine runs", res);
  }

  TEST_F(Existing_Coroutine, SelfKill)
  {
    RunLua(state, R"(
      _G.test_killed = "thread did not run"
      ForkThread(function()
        local me = CurrentThread()
        KillThread(me)
        _G.test_killed = "stopped at the second KillThread"
        KillThread(me)
        _G.test_killed = "reached the end"
      end)
    )");
    stage.UserFrame();
    const std::string res = RunLua(state, "return _G.test_killed");
    Assert(res == "reached the end", "a thread killing itself twice runs on, as in the binary", res);
  }

  TEST_F(Existing_Coroutine, InheritGlobals)
  {
    const std::string res = RunLua(state, R"(
      local env = setmetatable({marker = "parent"}, {__index = _G})
      local outer = coroutine.create(function()
        setfenv(0, env)
        local inner = coroutine.create(function() return getfenv(0).marker end)
        local _, marker = coroutine.resume(inner)
        return marker
      end)
      local _, marker = coroutine.resume(outer)
      return tostring(marker)
    )");
    Assert(res == "parent", "a coroutine created inside a coroutine inherits its parent's globals", res);
  }

  TEST_F(Existing_Coroutine, RestoredWithoutWrapper)
  {
    lua_State* const L = state.GetCState();
    const char* const body = "return CurrentThread() == test_restored";
    lua_State* const restored = lua_newthread(L);
    lua_pushstring(L, "test_restored");
    lua_insert(L, -2);
    lua_settable(L, LUA_GLOBALSINDEX);
    luaL_loadbuffer(L, body, std::strlen(body), "=restored");
    lua_xmove(L, restored, 1);
    Assert(restored->stateUserData == nullptr, "a thread made without a wrapper has none");

    const std::string res = RunLua(state, R"(
      local ok, same = coroutine.resume(test_restored)
      test_restored = nil
      return tostring(ok) .. " " .. tostring(same)
    )");
    Assert(res == "true true", "a coroutine without a wrapper can call engine functions after a resume", res);
  }

  TEST_F(Existing_Coroutine, GarbageCollectionWeakTables)
  {
    const std::string res = RunLua(state, R"(
      -- Verify with weak-value and weak-key tables that unreferenced coroutines
      -- in various states (suspended at start, yielded, dead) are swept.
      local weakValues = setmetatable({}, { __mode = "v" })
      local weakKeys = setmetatable({}, { __mode = "k" })

      -- Case A: Coroutine never resumed (suspended at start)
      local co_never = coroutine.create(function() end)
      weakValues["never"] = co_never
      weakKeys[co_never] = "never"

      -- Case B: Coroutine yielded mid-execution (suspended)
      local co_yielded = coroutine.create(function() coroutine.yield(42) end)
      coroutine.resume(co_yielded)
      weakValues["yielded"] = co_yielded
      weakKeys[co_yielded] = "yielded"

      -- Case C: Coroutine completed (dead)
      local co_dead = coroutine.create(function() return 100 end)
      coroutine.resume(co_dead)
      weakValues["dead"] = co_dead
      weakKeys[co_dead] = "dead"

      -- Confirm initial presence
      if weakValues["never"] == nil or weakValues["yielded"] == nil or weakValues["dead"] == nil then
        return "coroutines missing from weakValues table"
      end

      -- With strong references held, collectgarbage() must NOT collect them
      collectgarbage()
      if weakValues["never"] ~= co_never or weakValues["yielded"] ~= co_yielded or weakValues["dead"] ~= co_dead then
        return "referenced coroutines collected prematurely"
      end
      if weakKeys[co_never] ~= "never" or weakKeys[co_yielded] ~= "yielded" or weakKeys[co_dead] ~= "dead" then
        return "referenced coroutine keys collected prematurely"
      end

      -- Drop strong references
      co_never = nil
      co_yielded = nil
      co_dead = nil

      -- Trigger garbage collection
      collectgarbage()
      collectgarbage()

      -- Verify they are collected and removed from weak tables
      if weakValues["never"] ~= nil then
        return "unreferenced suspended coroutine was not collected from weakValues"
      end
      if weakValues["yielded"] ~= nil then
        return "unreferenced yielded coroutine was not collected from weakValues"
      end
      if weakValues["dead"] ~= nil then
        return "unreferenced dead coroutine was not collected from weakValues"
      end

      local keyCount = 0
      for k, v in pairs(weakKeys) do
        keyCount = keyCount + 1
      end
      if keyCount ~= 0 then
        return "unreferenced coroutines still present in weakKeys: " .. tostring(keyCount)
      end

      -- Verify that tables held only on a coroutine stack are collected when the coroutine is collected
      local weakStackObj = setmetatable({}, { __mode = "v" })
      local co_stack = coroutine.create(function()
        local frameObj = { payload = "stack_payload_123" }
        weakStackObj[1] = frameObj
        coroutine.yield()
        frameObj = nil
      end)
      coroutine.resume(co_stack)

      -- At this point, frameObj is reachable ONLY through co_stack's live stack
      collectgarbage()
      if weakStackObj[1] == nil or weakStackObj[1].payload ~= "stack_payload_123" then
        return "stack object was prematurely collected while coroutine is alive"
      end

      -- Drop reference to the coroutine
      co_stack = nil
      collectgarbage()
      collectgarbage()

      if weakStackObj[1] ~= nil then
        return "stack object was not collected after unreferenced coroutine was collected"
      end

      return "ok"
    )");
    Assert(res == "ok", "coroutine collection in weak tables (values and keys) and stack object cleanup", res);
  }

  TEST_F(Existing_Coroutine, ThreadGcList)
  {
    lua_State* const L = state.GetCState();
    const int baselineThreads = CountCoroutineThreads(L);

    // Create 6 coroutines referenced in a Lua table
    RunLua(state, R"(
      _G.test_held_coroutines = {}
      for i = 1, 6 do
        local co = coroutine.create(function() coroutine.yield(i) end)
        coroutine.resume(co)
        table.insert(_G.test_held_coroutines, co)
      end
    )");

    const int heldThreads = CountCoroutineThreads(L);
    Assert(heldThreads == baselineThreads + 6, "rootgc1 tracks exactly 6 live coroutine threads when referenced");

    // GC while referenced must preserve them
    RunLua(state, "collectgarbage()");
    Assert(CountCoroutineThreads(L) == baselineThreads + 6, "rootgc1 retains all coroutine threads while referenced");

    // Release half (3) of the references
    RunLua(state, R"(
      _G.test_held_coroutines[1] = nil
      _G.test_held_coroutines[2] = nil
      _G.test_held_coroutines[3] = nil
      collectgarbage()
      collectgarbage()
    )");
    Assert(CountCoroutineThreads(L) == baselineThreads + 3, "rootgc1 frees exactly the 3 unreferenced coroutines and retains the 3 referenced ones");

    // Drop all remaining references and collect garbage
    RunLua(state, R"(
      _G.test_held_coroutines = nil
      collectgarbage()
      collectgarbage()
    )");

    const int clearedThreads = CountCoroutineThreads(L);
    Assert(clearedThreads == baselineThreads, "rootgc1 unlinks and frees all coroutine threads when unreferenced");
  }

  TEST_F(Existing_Coroutine, StressAllocation)
  {
    lua_State* const L = state.GetCState();
    const int baselineThreads = CountCoroutineThreads(L);

    const std::string res = RunLua(state, R"(
      for i = 1, 100 do
        local co1 = coroutine.create(function() coroutine.yield(1) end)
        coroutine.resume(co1)
        local co2 = coroutine.create(function() return 2 end)
        coroutine.resume(co2)
        local co3 = coroutine.create(function() end)
        -- co3 never resumed
      end
      collectgarbage()
      collectgarbage()
      return "ok"
    )");
    Assert(res == "ok", "stress test creating and abandoning 300 coroutines runs cleanly");
    Assert(CountCoroutineThreads(L) == baselineThreads, "all 300 abandoned coroutines swept from rootgc1");
  }
} // namespace
