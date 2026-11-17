// Engine addition (dedicated-server plan WPL.2): checks that the Linux and macOS toolchains
// build code the way the engine's simulation needs, and prints the facts later work depends on
// (data model, default floating-point environment).

#include <gtest/gtest.h>

#include <cfloat>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <limits>
#include <print>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "platform/FpControl.h"

namespace
{
#if FAFRE_ARCH_X64
  std::uint16_t ReadX87ControlWord()
  {
    std::uint16_t cw = 0;
    __asm__ __volatile__("fnstcw %0" : "=m"(cw));
    return cw;
  }
#endif

  // The thread's floating-point control state, printed.
  std::string FloatingPointControl()
  {
#if FAFRE_ARCH_X64
    return std::format("fcw=0x{:04X} mxcsr=0x{:08X}", ReadX87ControlWord(), platform::ReadMxcsr());
#else
    return std::format("fpcr=0x{:08X}", platform::ReadFpcr());
#endif
  }

  // Out of line, so the conversion happens at run time on the value passed.
  [[gnu::noinline]] int ToInt(
    const float value
  )
  {
    return static_cast<int>(value);
  }

  // Kept out of line so the compiler sees a*b+c as one expression it could
  // contract; with -ffp-contract=off it must round the product first.
  [[gnu::noinline]] double MulAdd(
    const double a,
    const double b,
    const double c
  )
  {
    return a * b + c;
  }

  extern "C" [[gnu::noinline]] void ThrowFromExternC()
  {
    throw std::runtime_error("from extern C");
  }
} // namespace

TEST(
  LinuxToolchain,
  PrintsDataModel
)
{
  std::printf(
    "sizeof(long)=%zu sizeof(void*)=%zu sizeof(wchar_t)=%zu FLT_EVAL_METHOD=%d\n",
    sizeof(long),
    sizeof(void*),
    sizeof(wchar_t),
    static_cast<int>(FLT_EVAL_METHOD)
  );
}

TEST(
  LinuxToolchain,
  PlainCharIsSigned
)
{
  EXPECT_LT(static_cast<char>(0xFF), 0);
}

// 1 + 2^-30 squared minus (1 + 2^-29): exactly 2^-60 with a fused
// multiply-add, 0 with the product rounded to double first.
TEST(
  LinuxToolchain,
  NoFmaContraction
)
{
  const double x = 1.0 + 0x1p-30;
  EXPECT_EQ(MulAdd(x, x, -(1.0 + 0x1p-29)), 0.0);
}

TEST(
  LinuxToolchain,
  ExceptionLeavesExternC
)
{
  bool caught = false;
  try {
    ThrowFromExternC();
  } catch (const std::runtime_error& e) {
    caught = std::strcmp(e.what(), "from extern C") == 0;
  }
  EXPECT_TRUE(caught);
}

TEST(
  LinuxToolchain,
  ThreadRuns
)
{
  std::vector<std::string> fromThread;
  std::thread worker([&fromThread] {
    std::println("worker thread: {}", FloatingPointControl());
    fromThread.emplace_back("worker");
  });
  worker.join();
  EXPECT_EQ(fromThread.size(), 1u);
}

TEST(
  LinuxToolchain,
  NoFtzOrDazByDefault
)
{
  std::println("main thread:   {}", FloatingPointControl());
#if FAFRE_ARCH_X64
  EXPECT_EQ(platform::ReadMxcsr() & 0x8040u, 0u);
#else
  EXPECT_EQ(platform::ReadFpcr(), platform::kSimFpcr);
#endif
}

#if FAFRE_ARCH_ARM64
// A new thread starts at FPCR 0 even when its creator runs with flush-to-zero (FPCR.FZ, bit 24)
// and default NaN (bit 25): the kernel gives it the default, not the creator's value. The engine
// relies on it instead of wrapping thread creation (platform/FpControl.h).
TEST(
  LinuxToolchain,
  NewThreadStartsAtDefaultFpcr
)
{
  const std::uint64_t saved = platform::ReadFpcr();
  platform::WriteFpcr(saved | (1ull << 24) | (1ull << 25));
  std::uint64_t seen = ~0ull;
  std::thread worker([&seen] {
    seen = platform::ReadFpcr();
  });
  worker.join();
  platform::WriteFpcr(saved);
  EXPECT_EQ(seen, platform::kSimFpcr);
}
#endif

// Float-to-int conversions that are out of range saturate, and NaN gives 0, with
// -fno-strict-float-cast-overflow on every target (the x86-64 build's cvttss2si sequence and
// ARM64's fcvtzs agree): code that needs the x87's 0x80000000 calls fa::TruncateToInt.
TEST(
  LinuxToolchain,
  FloatToIntSaturates
)
{
  EXPECT_EQ(ToInt(std::numeric_limits<float>::quiet_NaN()), 0);
  EXPECT_EQ(ToInt(3.0e9f), std::numeric_limits<int>::max());
  EXPECT_EQ(ToInt(-3.0e9f), std::numeric_limits<int>::min());
  EXPECT_EQ(ToInt(-1.5f), -1);
}
