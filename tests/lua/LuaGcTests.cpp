// Both collectors. LuaGc drives the shipped 5.0 stop-the-world collector every game state uses
// (collectgarbage, weak tables, roots held from C++). LuaIncrementalGc drives the engine's
// Lua 5.1-style incremental collector (LuaIncrementalGcCore.inc), which only the two UI states
// use with lua_IncrementalGC on: the tests switch it on, open a state registered as the front-end
// UI VM, and drive it as UI_ProcessIdleGC (CUIManager.cpp) does - faf_lua51_gc_slice with a work
// budget - and as allocation does through luaC_checkGC.

#include <memory>
#include <string>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"
#include "lua/LuaIncrementalGc.h"

namespace
{
  using LuaPlus::LuaObject;
  using LuaPlus::LuaState;

  class LuaGc : public faf_lua_tests::LuaFixture
  {
  protected:
    int CountKb() { return lua_getgccount(L()); }
  };

  TEST_F(LuaGc, CollectFreesUnreachableObjects)
  {
    Run("big = {} for i = 1, 20000 do big[i] = {i, 'payload' .. i} end");
    const int withGarbage = CountKb();
    Run("big = nil collectgarbage()");
    const int afterCollect = CountKb();
    EXPECT_LT(afterCollect, withGarbage);
    EXPECT_LT(afterCollect, withGarbage / 2) << withGarbage << " KB -> " << afterCollect << " KB";
  }

  // 5.0 weak tables: a weak entry goes when its object is collected; strings, numbers and booleans
  // are values, never weak.
  TEST_F(LuaGc, WeakTables)
  {
    EXPECT_TRUE(Bool(R"(
      local wv = setmetatable({}, {__mode = 'v'})
      local wk = setmetatable({}, {__mode = 'k'})
      local wkv = setmetatable({}, {__mode = 'kv'})
      local keep = {}
      wv[1] = {} wv[2] = keep wv[3] = 'string' wv[4] = 5 wv[5] = true
      wk[{}] = 1 wk[keep] = 2 wk['strkey'] = 3
      wkv[{}] = 'a' wkv['s'] = {} wkv[keep] = keep
      collectgarbage()
      local wkCount = 0
      for k, v in pairs(wk) do wkCount = wkCount + 1 end
      local wkvCount = 0
      for k, v in pairs(wkv) do wkvCount = wkvCount + 1 end
      return wv[1] == nil and wv[2] == keep and wv[3] == 'string' and wv[4] == 5 and wv[5] == true
         and wkCount == 2 and wk[keep] == 2 and wk.strkey == 3
         and wkvCount == 1 and wkv[keep] == keep)"));
  }

  TEST_F(LuaGc, ReachableGraphsSurvive)
  {
    EXPECT_EQ(Num(R"(
      local function make()
        local hidden = {count = 0}
        return function() hidden.count = hidden.count + 1 return hidden.count end
      end
      counter = make()
      ring = {} ring.next = {back = ring} ring.next.next = {back = ring.next}
      for i = 1, 3 do collectgarbage() end
      counter() counter()
      return counter() + (ring.next.next.back.back == ring and 100 or 0))"), 103.0);
  }

  TEST_F(LuaGc, ThresholdAndGcinfo)
  {
    Run("collectgarbage(1000000)");
    EXPECT_EQ(Num("local count, threshold = gcinfo() return threshold"), 1000000.0);
    // A threshold below the count collects at once and resets the threshold above the live heap.
    Run("collectgarbage(0)");
    EXPECT_TRUE(Bool("local count, threshold = gcinfo() return threshold >= count"));
  }

  TEST_F(LuaGc, StringsAreInternedAndCollected)
  {
    EXPECT_TRUE(Bool(R"(
      local parts = {}
      for i = 1, 5000 do parts[i] = 'str' .. i end
      parts = nil
      collectgarbage()
      local a = 'str' .. 42
      local b = 'str' .. '42'
      return a == b)"));
  }

  // ---------------------------------------------------------------------------------------------

  class LuaIncrementalGc : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      mPrevious = moho::lua_IncrementalGC;
      moho::lua_IncrementalGC = true;
      mState = std::make_unique<LuaState>(
        LuaState::LIB_BASE, static_cast<int>(moho::lua_incremental::ELuaVmRole::FrontendUi)
      );
    }

    void TearDown() override
    {
      mState.reset();
      moho::lua_IncrementalGC = mPrevious;
    }

    lua_State* L() const { return mState->GetCState(); }
    global_State* G() const { return L()->l_G; }

    LuaObject Run(const std::string& source)
    {
      const int top = lua_gettop(L());
      if (luaL_loadbuffer(L(), source.data(), source.size(), "=test") != 0 || LuaCallProtected(L(), 0, 1) != 0) {
        const char* const message = lua_tostring(L(), -1);
        ADD_FAILURE() << (message != nullptr ? message : "error") << "\nin: " << source;
        lua_settop(L(), top);
        return LuaObject(mState.get());
      }
      LuaObject result(mState.get(), -1);
      lua_settop(L(), top);
      return result;
    }

    bool Bool(const std::string& source)
    {
      const LuaObject result = Run(source);
      EXPECT_TRUE(result.IsBoolean()) << source;
      return result.IsBoolean() && result.GetBoolean();
    }

    /** Slices with `budget` until the cycle reaches its pause again; the number of slices it took. */
    int FinishCycle(const int budget)
    {
      int slices = 1;
      bool done = faf_lua51_gc_slice(L(), budget, true);
      while (!done && slices < 1000000) {
        done = faf_lua51_gc_slice(L(), budget, false);
        ++slices;
      }
      EXPECT_TRUE(done);
      return slices;
    }

    std::unique_ptr<LuaState> mState;
    bool mPrevious = false;
  };

  TEST_F(LuaIncrementalGc, StateIsRegisteredAsAUiVm)
  {
    EXPECT_TRUE(moho::lua_incremental::UsesIncrementalGc(G()));
    const moho::lua_incremental::SState* const collector = moho::lua_incremental::Find(G());
    ASSERT_NE(collector, nullptr);
    EXPECT_TRUE(collector->initialized);
    EXPECT_EQ(collector->state, moho::lua_incremental::EState::Pause);

    // A state opened for any other role keeps the shipped collector.
    LuaState baseline(LuaState::LIB_BASE);
    EXPECT_FALSE(moho::lua_incremental::UsesIncrementalGc(baseline.GetCState()->l_G));
  }

  TEST_F(LuaIncrementalGc, FullCycleClearsWeakEntriesAndKeepsLiveOnes)
  {
    Run(R"(
      keep = {name = 'kept', list = {1, 2, 3}}
      weak = setmetatable({}, {__mode = 'v'})
      weak[1] = {} weak[2] = keep weak[3] = 'string'
      weakKeys = setmetatable({}, {__mode = 'k'})
      weakKeys[{}] = true weakKeys[keep] = true
      garbage = {} for i = 1, 5000 do garbage[i] = {i} end
      garbage = nil)");
    const int before = lua_getgccount(L());
    faf_lua51_gc_full(L());
    EXPECT_LT(lua_getgccount(L()), before);
    EXPECT_TRUE(Bool(R"(
      local n = 0 for k in pairs(weakKeys) do n = n + 1 end
      return weak[1] == nil and weak[2] == keep and weak[3] == 'string' and n == 1
         and keep.name == 'kept' and keep.list[3] == 3)"));
  }

  // UI_ProcessIdleGC's way: a forced start, then small slices until the cycle ends. A small budget
  // must take several slices, and the result must be the full cycle's.
  TEST_F(LuaIncrementalGc, SlicesFinishACycle)
  {
    Run(R"(
      keep = {}
      for i = 1, 2000 do keep[i] = {value = i, text = 'k' .. i} end
      weak = setmetatable({}, {__mode = 'v'})
      for i = 1, 500 do weak[i] = {i} end)");
    const int slices = FinishCycle(64);
    EXPECT_GT(slices, 1);
    EXPECT_TRUE(Bool(R"(
      for i = 1, 500 do if weak[i] ~= nil then return false end end
      local sum = 0 for i = 1, 2000 do sum = sum + keep[i].value end
      return sum == 2001000 and keep[1234].text == 'k1234')"));
    // Once paused, a slice without a forced start does nothing until the heap reaches the threshold.
    EXPECT_TRUE(faf_lua51_gc_slice(L(), 64, false));
  }

  // The write barriers: while a cycle is under way, new objects are stored into tables the
  // collector may already have marked, the old references are dropped, and the cycle continues.
  // Everything still reachable must come through intact.
  TEST_F(LuaIncrementalGc, MutationDuringACycleKeepsReachableObjects)
  {
    Run(R"(
      holder = {}
      for i = 1, 300 do holder[i] = {seed = i} end
      function mutate(round)
        for i = 1, 300 do
          local fresh = {seed = i, round = round, name = 'n' .. round .. '_' .. i, sub = {round}}
          holder[i] = fresh
        end
        holder.extra = {list = {}}
        for j = 1, 50 do holder.extra.list[j] = {j * round} end
        local closureCount = 0
        holder.fn = function() closureCount = closureCount + 1 return closureCount + round end
      end
      function verify(round)
        for i = 1, 300 do
          local h = holder[i]
          if h.seed ~= i or h.round ~= round or h.name ~= ('n' .. round .. '_' .. i) or h.sub[1] ~= round then return false end
        end
        for j = 1, 50 do if holder.extra.list[j][1] ~= j * round then return false end end
        return holder.fn() == round + 1
      end)");
    for (int round = 1; round <= 12; ++round) {
      bool done = faf_lua51_gc_slice(L(), 32 + round * 16, true);
      for (int step = 0; step < round && !done; ++step) {
        done = faf_lua51_gc_slice(L(), 48, false);
      }
      Run("mutate(" + std::to_string(round) + ")");
      while (!done) {
        done = faf_lua51_gc_slice(L(), 48, false);
      }
      faf_lua51_gc_full(L());
      EXPECT_TRUE(Bool("return verify(" + std::to_string(round) + ")")) << "round " << round;
    }
  }

  // Allocation alone drives the collector through luaC_checkGC -> faf_lua51_gc_step while the
  // state is not frame-driven: a long run of short-lived tables keeps the heap bounded.
  TEST_F(LuaIncrementalGc, AllocationDrivesSteps)
  {
    const int before = lua_getgccount(L());
    Run("for i = 1, 200000 do local t = {i, i + 1} end");
    const int after = lua_getgccount(L());
    EXPECT_LT(after, before + 4096) << before << " KB -> " << after << " KB"; // 200000 tables would be ~8 MB
    EXPECT_TRUE(Bool("local t = {} for i = 1, 1000 do t[i] = i end return t[1000] == 1000"));
  }

  // In a frame-driven state, collectgarbage() runs the incremental collector's full cycle
  // (luaB_collectgarbage's engine addition).
  TEST_F(LuaIncrementalGc, CollectgarbageRunsAFullCycleWhenFrameDriven)
  {
    (void)FinishCycle(1 << 20); // makes the state frame-driven
    const moho::lua_incremental::SState* const collector = moho::lua_incremental::Find(G());
    ASSERT_NE(collector, nullptr);
    EXPECT_TRUE(collector->frameDriven);
    EXPECT_TRUE(Bool(R"(
      local weak = setmetatable({}, {__mode = 'k'})
      weak[{}] = 1
      local keep = {}
      weak[keep] = 2
      collectgarbage()
      local n = 0 for k in pairs(weak) do n = n + 1 end
      return n == 1 and weak[keep] == 2)"));
  }

  // Coroutines and their open upvalues across slices.
  TEST_F(LuaIncrementalGc, CoroutinesAndUpvaluesAcrossSlices)
  {
    Run(R"(
      co = coroutine.create(function()
        local acc = {}
        for i = 1, 100 do
          acc[i] = {i}
          coroutine.yield(table.getn(acc))
        end
        return acc[100][1]
      end))");
    bool done = faf_lua51_gc_slice(L(), 32, true);
    for (int i = 0; i < 99; ++i) {
      EXPECT_TRUE(Bool("local ok, n = coroutine.resume(co) return ok and n == " + std::to_string(i + 1)));
      if (!done) {
        done = faf_lua51_gc_slice(L(), 32, false);
      } else {
        done = faf_lua51_gc_slice(L(), 32, true);
      }
    }
    while (!done) {
      done = faf_lua51_gc_slice(L(), 32, false);
    }
    EXPECT_TRUE(Bool("local ok, n = coroutine.resume(co) return ok and n == 100"));
    EXPECT_TRUE(Bool("local ok, v = coroutine.resume(co) return ok and v == 100 and coroutine.status(co) == 'dead'"));
  }

  // A C++ root held across incremental cycles stays alive.
  TEST_F(LuaIncrementalGc, LuaObjectRootsSurvive)
  {
    LuaObject held;
    held.AssignNewTable(mState.get(), 0, 0);
    held.SetString("v", "rooted");
    LuaObject text;
    text.AssignString(mState.get(), "rooted string");
    for (int i = 0; i < 3; ++i) {
      Run("local junk = {} for i = 1, 3000 do junk[i] = {} end");
      (void)FinishCycle(256);
    }
    faf_lua51_gc_full(L());
    EXPECT_STREQ(held["v"].GetString(), "rooted");
    EXPECT_STREQ(text.GetString(), "rooted string");
  }

  // Abandoning mid-cycle finishes it, drops the registration and hands the state back to the
  // shipped collector, which then collects as before.
  TEST_F(LuaIncrementalGc, AbandonReturnsToTheShippedCollector)
  {
    Run("keep = {x = 1} for i = 1, 3000 do local t = {i} end");
    (void)faf_lua51_gc_slice(L(), 16, true);
    faf_lua51_gc_abandon(G());
    EXPECT_FALSE(moho::lua_incremental::UsesIncrementalGc(G()));
    EXPECT_EQ(moho::lua_incremental::Find(G()), nullptr);
    EXPECT_TRUE(Bool(R"(
      local weak = setmetatable({}, {__mode = 'v'})
      weak[1] = {} weak[2] = keep
      collectgarbage()
      return weak[1] == nil and weak[2] == keep and keep.x == 1)"));
  }
} // namespace
