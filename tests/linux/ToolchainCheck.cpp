// Engine addition (dedicated-server plan WPL.2): checks that the Linux toolchain
// builds code the way the engine's simulation needs, and prints the facts later
// work depends on (data model, default floating-point environment).

#include <gtest/gtest.h>

#include <cfloat>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace
{
  std::uint16_t ReadX87ControlWord()
  {
    std::uint16_t cw = 0;
    __asm__ __volatile__("fnstcw %0" : "=m"(cw));
    return cw;
  }

  std::uint32_t ReadMxcsr()
  {
    std::uint32_t mxcsr = 0;
    __asm__ __volatile__("stmxcsr %0" : "=m"(mxcsr));
    return mxcsr;
  }

  // Kept out of line so the compiler sees a*b+c as one expression it could
  // contract; with -ffp-contract=off it must round the product first.
  [[gnu::noinline]] double MulAdd(const double a, const double b, const double c)
  {
    return a * b + c;
  }

  extern "C" [[gnu::noinline]] void ThrowFromExternC()
  {
    throw std::runtime_error("from extern C");
  }
} // namespace

TEST(LinuxToolchain, PrintsDataModel)
{
  std::printf("sizeof(long)=%zu sizeof(void*)=%zu sizeof(wchar_t)=%zu FLT_EVAL_METHOD=%d\n", sizeof(long),
              sizeof(void*), sizeof(wchar_t), static_cast<int>(FLT_EVAL_METHOD));
}

TEST(LinuxToolchain, PlainCharIsSigned)
{
  EXPECT_LT(static_cast<char>(0xFF), 0);
}

// 1 + 2^-30 squared minus (1 + 2^-29): exactly 2^-60 with a fused
// multiply-add, 0 with the product rounded to double first.
TEST(LinuxToolchain, NoFmaContraction)
{
  const double x = 1.0 + 0x1p-30;
  EXPECT_EQ(MulAdd(x, x, -(1.0 + 0x1p-29)), 0.0);
}

TEST(LinuxToolchain, ExceptionLeavesExternC)
{
  bool caught = false;
  try {
    ThrowFromExternC();
  } catch (const std::runtime_error& e) {
    caught = std::strcmp(e.what(), "from extern C") == 0;
  }
  EXPECT_TRUE(caught);
}

TEST(LinuxToolchain, ThreadRuns)
{
  std::vector<std::string> fromThread;
  std::thread worker([&fromThread] {
    std::printf("worker thread: fcw=0x%04X mxcsr=0x%08X\n", ReadX87ControlWord(), ReadMxcsr());
    fromThread.emplace_back("worker");
  });
  worker.join();
  EXPECT_EQ(fromThread.size(), 1u);
}

TEST(LinuxToolchain, NoFtzOrDazByDefault)
{
  std::printf("main thread:   fcw=0x%04X mxcsr=0x%08X\n", ReadX87ControlWord(), ReadMxcsr());
  EXPECT_EQ(ReadMxcsr() & 0x8040u, 0u);
}
