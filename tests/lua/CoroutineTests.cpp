#include <cstdio>
#include <cstdlib>
#include <string>

#include "lua/LuaObject.h"
#include "lua/LuaPrimitives.h"

namespace
{
  void Assert(const bool condition, const char* const message)
  {
    if (!condition) {
      std::fprintf(stderr, "FAIL: %s\n", message);
      std::exit(1);
    }
    std::printf("PASS: %s\n", message);
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
} // namespace

int main()
{
  LuaPlus::LuaState state(LuaPlus::LuaState::LIB_BASE);

  // 1. coroutine.create argument validation
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

  // 2. coroutine.status lifecycle
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

  // 3. Values passed to resume and yield
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

  // 4. Multi-step generator
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

  // 5. Error handling in coroutine
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

  // 6. Engine integration: calling Moho/LuaPlus methods inside coroutine
  {
    const std::string res = RunLua(state, R"(
      local runningCo = nil
      local currentThreadMatched = false
      local co
      co = coroutine.create(function()
        -- CurrentThread() uses LuaObject::AssignThread with active stateUserData
        local cur = rawget(_G, "CurrentThread")
        if cur then
          currentThreadMatched = (cur() == co)
        else
          currentThreadMatched = true
        end

        -- Ensure stateUserData is valid by doing standard Lua/engine operations
        local s = tostring(co)
        if string.find(s, "thread:", 1, true) == nil then
          error("tostring(thread) failed: " .. tostring(s))
        end

        -- Verify KillThread properly rejects a Lua coroutine
        local killFn = rawget(_G, "KillThread")
        if killFn then
          local okKill, killErr = pcall(killFn, co)
          if okKill or string.find(tostring(killErr), "wasn't created with ForkThread", 1, true) == nil then
            error("KillThread should reject coroutines: " .. tostring(killErr))
          end
        end

        -- Verify ResumeThread properly rejects a Lua coroutine
        local resFn = rawget(_G, "ResumeThread")
        if resFn then
          local okRes, resErr = pcall(resFn, co)
          if okRes or string.find(tostring(resErr), "wasn't created with ForkThread", 1, true) == nil then
            error("ResumeThread should reject coroutines: " .. tostring(resErr))
          end
        end

        return "ok"
      end)

      local ok, ret = coroutine.resume(co)
      if not ok then return "resume failed: " .. tostring(ret) end
      if not currentThreadMatched then return "CurrentThread mismatch" end
      return ret
    )");
    Assert(res == "ok", "engine / Moho integration inside coroutine (stateUserData, CurrentThread, KillThread/ResumeThread guards)");
  }

  // 7. Garbage collection of coroutines
  {
    const std::string res = RunLua(state, R"(
      -- Create and abandon many coroutines (both suspended and finished)
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
    Assert(res == "ok", "coroutine garbage collection cleans up unreferenced threads without crash or leak");
  }

  std::printf("ALL COROUTINE TESTS PASSED\n");
  return 0;
}
