// gpg/core/utils (ParseNum, the die handler, LocalCache) and gpg/core/time (Timer and the cycle conversions).
// ParseNum's expected values follow the retail instructions at 0x008D8FA0, including its handling of capital
// letters: only 'A' passes the letter check (`sub bl, 41h; jne fail`), and it then counts as 'A' - 'W' = -22.

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <gtest/gtest.h>

#include "CoreTestSupport.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/LocalCache.h"

namespace
{
  bool Parse(const char* const text, int* const out)
  {
    return gpg::ParseNum(text, text + std::char_traits<char>::length(text), out);
  }

  // ---------------------------------------------------------------------------------------------
  // ParseNum
  // ---------------------------------------------------------------------------------------------

  TEST(GpgParseNum, DecimalHexAndOctal)
  {
    int value = 0;
    EXPECT_TRUE(Parse("12345", &value));
    EXPECT_EQ(value, 12345);
    EXPECT_TRUE(Parse("-42", &value));
    EXPECT_EQ(value, -42);
    EXPECT_TRUE(Parse("0x1f", &value));
    EXPECT_EQ(value, 31);
    EXPECT_TRUE(Parse("-0xff", &value));
    EXPECT_EQ(value, -255);
    EXPECT_TRUE(Parse("017", &value)); // a leading 0 is octal
    EXPECT_EQ(value, 15);
    EXPECT_TRUE(Parse("0", &value));
    EXPECT_EQ(value, 0);
    EXPECT_TRUE(Parse("7", &value));
    EXPECT_EQ(value, 7);
  }

  TEST(GpgParseNum, StopsAtTheEndPointer)
  {
    const char* const text = "123456";
    int value = 0;
    EXPECT_TRUE(gpg::ParseNum(text, text + 3, &value));
    EXPECT_EQ(value, 123);
    // The end test (`cmp ecx, ebp; jne` at 0x008D9013) comes after the first digit, when the cursor has
    // already passed an empty range's end: such a range reads on to the terminator.
    EXPECT_TRUE(gpg::ParseNum(text, text, &value));
    EXPECT_EQ(value, 123456);
  }

  TEST(GpgParseNum, RejectsBadDigitsAndLeavesTheOutputAlone)
  {
    int value = 99;
    EXPECT_FALSE(Parse("", &value));
    EXPECT_FALSE(Parse("-", &value));
    EXPECT_FALSE(Parse("08", &value));   // 8 is not octal
    EXPECT_FALSE(Parse("12a", &value));  // 'a' is 10, not below 10
    EXPECT_FALSE(Parse("0xg", &value));
    EXPECT_FALSE(Parse("0xB", &value));  // capitals other than A fail the letter check
    EXPECT_FALSE(Parse(" 1", &value));
    EXPECT_FALSE(Parse("1 ", &value));
    EXPECT_EQ(value, 99);
  }

  TEST(GpgParseNum, CapitalAIsTheRetailQuirk)
  {
    // 0x008D8FF1: `sub bl, 41h; jne` lets 'A' through, then `sub eax, 57h` makes it -22, below any base.
    int value = 0;
    EXPECT_TRUE(Parse("0xA", &value));
    EXPECT_EQ(value, -22);
    EXPECT_TRUE(Parse("0x1A", &value));
    EXPECT_EQ(value, 16 - 22);
  }

  // ---------------------------------------------------------------------------------------------
  // Die handler
  // ---------------------------------------------------------------------------------------------

  std::string gCaptured;
  void Capture(const char* const message) { gCaptured = message != nullptr ? message : ""; }

  TEST(GpgDieHandler, SetReturnsThePreviousHandlerAndAssertionsReachIt)
  {
    const gpg::die_handler_t previous = gpg::SetDieHandler(&Capture);
    EXPECT_NE(previous, nullptr); // the suite's own handler (CoreTestSupport.cpp)

    gpg::InvokeDieHandler("direct");
    EXPECT_EQ(gCaptured, "direct");

    gpg::HandleAssertFailure("x == y", 42, "c:\\some\\file.cpp");
    EXPECT_EQ(gCaptured, "Failed assertion: x == y\nFile: c:\\some\\file.cpp\nLine: 42");

    EXPECT_EQ(gpg::SetDieHandler(previous), &Capture);
  }

  // ---------------------------------------------------------------------------------------------
  // LocalCache
  // ---------------------------------------------------------------------------------------------

  TEST(GpgLocalCache, ExecutableIdentityIsStableAndReadTheExe)
  {
    const std::uint64_t identity = gpg::ExecutableIdentity();
    EXPECT_EQ(gpg::ExecutableIdentity(), identity);
    // The FNV-1a offset basis is what comes back when the exe's size and time could not be read.
    EXPECT_NE(identity, 0xCBF29CE484222325ULL);
  }

  TEST(GpgLocalCache, DirectoryComesFromTheEnvironmentAndExists)
  {
    // The directory is fixed on first use, so this is the process's first call (nothing in this suite or in
    // the engine's static initialisers asks for it before).
    const faf_core_tests::TempDir folder;
    const std::filesystem::path wanted = folder.Path() / "cache";
#if defined(_WIN32)
    ASSERT_EQ(_putenv_s("FAF_SHADER_CACHE_DIR", wanted.string().c_str()), 0);
    const std::string& directory = gpg::LocalCacheDirectory();
    (void)_putenv_s("FAF_SHADER_CACHE_DIR", "");
#else
    ASSERT_EQ(setenv("FAF_SHADER_CACHE_DIR", wanted.string().c_str(), 1), 0);
    const std::string& directory = gpg::LocalCacheDirectory();
    (void)unsetenv("FAF_SHADER_CACHE_DIR");
#endif
    EXPECT_EQ(directory, wanted.string() + static_cast<char>(std::filesystem::path::preferred_separator));
    EXPECT_TRUE(std::filesystem::is_directory(wanted));
    EXPECT_EQ(&gpg::LocalCacheDirectory(), &directory);
  }

  // ---------------------------------------------------------------------------------------------
  // Timer
  // ---------------------------------------------------------------------------------------------

  LONGLONG Frequency()
  {
    LARGE_INTEGER frequency{};
    EXPECT_TRUE(::QueryPerformanceFrequency(&frequency));
    return frequency.QuadPart;
  }

  TEST(GpgTimer, GetCycleNeverGoesBack)
  {
    LONGLONG previous = gpg::time::GetCycle();
    for (int index = 0; index < 10000; ++index) {
      const LONGLONG now = gpg::time::GetCycle();
      ASSERT_GE(now, previous);
      previous = now;
    }
  }

  TEST(GpgTimer, ConversionsUseThePerformanceFrequency)
  {
    const LONGLONG frequency = Frequency();
    ASSERT_GT(frequency, 0);
    EXPECT_EQ(gpg::time::CyclesToMicroseconds(frequency), 1000000);
    EXPECT_EQ(gpg::time::CyclesToMicroseconds(frequency * 3), 3000000);
    EXPECT_EQ(gpg::time::CyclesToMicroseconds(0), 0);
    EXPECT_EQ(gpg::time::MicrosecondsToCycles(1000000), frequency);
    EXPECT_EQ(gpg::time::MicrosecondsToCycles(5000000), frequency * 5);

    // The float conversions round through a float; allow one part in a million.
    const double tolerance = static_cast<double>(frequency) * 1e-6 + 1.0;
    EXPECT_NEAR(static_cast<double>(gpg::time::SecondsToCycles(1.0f)), static_cast<double>(frequency), tolerance);
    EXPECT_NEAR(static_cast<double>(gpg::time::MillisecondsToCycles(1000.0f)), static_cast<double>(frequency), tolerance);
    EXPECT_NEAR(gpg::time::CyclesToSeconds(frequency), 1.0f, 1e-5f);
    EXPECT_NEAR(gpg::time::CyclesToMilliseconds(frequency), 1000.0f, 1e-2f);
  }

  TEST(GpgTimer, MicrosecondsRoundTrip)
  {
    for (const LONGLONG micro : {LONGLONG{1}, LONGLONG{999}, LONGLONG{123456}, LONGLONG{86400000000}}) {
      const LONGLONG back = gpg::time::CyclesToMicroseconds(gpg::time::MicrosecondsToCycles(micro));
      EXPECT_LE(back, micro);       // both directions truncate
      EXPECT_GE(back, micro - 1) << micro;
    }
  }

  TEST(GpgTimer, ElapsedTimeFollowsTheClock)
  {
    gpg::time::Timer timer;
    ::Sleep(30);
    const float milliseconds = timer.ElapsedMilliseconds();
    EXPECT_GE(milliseconds, 25.0f);
    EXPECT_LT(milliseconds, 5000.0f);
    EXPECT_GE(timer.ElapsedMicroseconds(), 25000);
    EXPECT_GE(timer.ElapsedSeconds(), 0.025f);

    const LONGLONG elapsed = timer.ElapsedCyclesAndReset();
    EXPECT_GE(elapsed, gpg::time::MillisecondsToCycles(25.0f));
    EXPECT_LT(timer.ElapsedCycles(), elapsed); // the baseline moved to now

    // Relative, not a fixed bound: a test on capped cores can be stalled for tens of milliseconds.
    ::Sleep(100);
    const float beforeReset = timer.ElapsedMilliseconds();
    timer.Reset();
    EXPECT_LT(timer.ElapsedMilliseconds(), beforeReset);
  }

  TEST(GpgTimer, SystemTimerIsOneObject)
  {
    const gpg::time::Timer& first = gpg::time::GetSystemTimer();
    EXPECT_EQ(&gpg::time::GetSystemTimer(), &first);
    EXPECT_GE(first.ElapsedCycles(), 0);
  }
} // namespace
