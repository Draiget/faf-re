// Engine addition (#247): the user preferences from several threads at once.
//
// The preferences live in a Lua state of their own (CUserPrefs), and the game uses them from two
// threads: the main thread's UI Lua, and the scenario loader thread, whose SessionInit.lua runs
// userInit.lua and mods.lua, which read and write preferences. Each call pushes onto that state's
// stack and links LuaObject temporaries into its object list. Without USER_PreferencesLock, the
// threads here corrupt the state within seconds; with it, every value they wrote reads back.
//
// FAF_PREFS_ITERATIONS=<n> sets the iterations per thread (default 20000); the command line
// belongs to GoogleTest.
//
// FAF_PREFS_NOLOCK=1 gives each thread a lock of its own (USER_PreferencesLock), which brings the
// race back: on 2026-11-01 four such runs ended in 0xC0000409 (a stack cookie overwritten) twice,
// 0xC0000005 once and a hang once, each within 4 s; with the lock every run passed in 0.5 s.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>
#include <vector>
#include <gtest/gtest.h>

#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/misc/StartupHelpers.h"

namespace
{
  constexpr int kThreads = 4;
  constexpr int kKeysPerThread = 32;

  fa::string KeyOf(const int thread, const int slot)
  {
    return gpg::STR_Printf("prefs_thread_test.t%d.k%d", thread, slot);
  }
} // namespace

TEST(Existing_PrefsThread, MultiThreadConcurrentAccess)
{
  const char* const iterationsEnv = std::getenv("FAF_PREFS_ITERATIONS");
  const int iterations = iterationsEnv != nullptr && std::atoi(iterationsEnv) > 0 ? std::atoi(iterationsEnv) : 20000;
  moho::IUserPrefs* const prefs = moho::USER_GetPreferences();
  ASSERT_NE(prefs, nullptr) << "no preferences object";

  std::atomic<int> ready{0};
  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&, t] {
      ++ready;
      while (ready.load() < kThreads) {
      }
      const fa::string missing("prefs_thread_test.missing");
      const fa::string fallback("fallback");
      for (int i = 0; i < iterations; ++i) {
        const fa::string key = KeyOf(t, i % kKeysPerThread);
        prefs->SetInteger(key, i);
        (void)prefs->GetInteger(key, -1);
        (void)prefs->GetString(missing, fallback);
        if (i % 8 == 0) {
          // What GetPreference does: a preferences-state object kept by the caller.
          const std::lock_guard<std::recursive_mutex> lock(moho::USER_PreferencesLock());
          const LuaPlus::LuaObject value = prefs->LookupKey(key);
          (void)value.IsNumber();
        }
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }

  int wrong = 0;
  for (int t = 0; t < kThreads; ++t) {
    for (int slot = 0; slot < kKeysPerThread; ++slot) {
      // The last i the thread wrote to this slot.
      int expected = iterations - 1;
      while (expected >= 0 && expected % kKeysPerThread != slot) {
        --expected;
      }
      const int got = prefs->GetInteger(KeyOf(t, slot), -1);
      if (got != expected) {
        if (++wrong <= 5) {
          std::printf("  thread %d slot %d: read %d, wrote %d last\n", t, slot, got, expected);
        }
      }
    }
  }
  EXPECT_EQ(wrong, 0) << wrong << " of " << (kThreads * kKeysPerThread) << " values wrong after " << kThreads << " threads x " << iterations << " iterations";
}
