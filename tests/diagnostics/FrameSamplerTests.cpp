// gpg/core/diagnostics/FrameSampler (Windows only): with FAF_FRAME_SAMPLER=<ms> the first FrameSamplerMark starts a
// thread that samples the marking thread's stack once a millisecond, and every frame of at least <ms> is reported as
// [FRAMESAMPLE] log lines; with FAF_FRAME_SAMPLER_DUMP=<path> each non-zero dbg_FrameSamplerPhase's whole stacks are
// appended to <path>.<phase>.folded when the phase changes. ctest sets both variables for this program
// (tests/diagnostics/CMakeLists.txt), since the threshold is read once per process.

#include "gpg/core/diagnostics/FrameSampler.h"
#include "gpg/core/utils/Logging.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace
{
  /** Collects [FRAMESAMPLE] lines; the sampler logs from its own thread. */
  class SampleLines final : public gpg::LogTarget
  {
  public:
    SampleLines()
      : gpg::LogTarget(true)
    {}

    void OnMessage(
      gpg::LogSeverity,
      const fa::string& message,
      const fa::vector<fa::string>&,
      int
    ) override
    {
      const std::string text = message.c_str();
      if (text.rfind("[FRAMESAMPLE]", 0) == 0) {
        const std::lock_guard<std::mutex> lock(mLock);
        mLines.push_back(text);
      }
    }

    std::vector<std::string> Lines()
    {
      const std::lock_guard<std::mutex> lock(mLock);
      return mLines;
    }

  private:
    std::mutex mLock;
    std::vector<std::string> mLines;
  };

  /** Keeps the CPU busy for `ms`, in a function of its own so it shows in the sampled stacks. */
  [[gnu::noinline]] void BusyFrame(
    const int ms
  )
  {
    std::atomic<unsigned> sink{0};
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < end) {
      sink.fetch_add(1, std::memory_order_relaxed);
    }
  }

  bool Contains(
    const std::vector<std::string>& lines,
    const std::string& part
  )
  {
    for (const std::string& line : lines) {
      if (line.contains(part)) {
        return true;
      }
    }
    return false;
  }
} // namespace

TEST(
  FrameSampler,
  ReportsSlowFramesAndDumpsEachPhase
)
{
  const char* const dump = std::getenv("FAF_FRAME_SAMPLER_DUMP");
  ASSERT_NE(std::getenv("FAF_FRAME_SAMPLER"), nullptr) << "run through ctest, which sets FAF_FRAME_SAMPLER";
  ASSERT_NE(dump, nullptr);
  const std::filesystem::path folded = std::string(dump) + ".1.folded";
  std::filesystem::remove(folded);

  SampleLines lines;
  gpg::diag::FrameSamplerMark(); // starts the sampler
  ASSERT_TRUE(Contains(lines.Lines(), "sampling this thread"));

  gpg::diag::dbg_FrameSamplerPhase = 1;
  for (int frame = 0; frame < 3; ++frame) {
    BusyFrame(40);
    gpg::diag::FrameSamplerMark();
  }
  gpg::diag::FrameSamplerMark(); // a short frame: not reported
  gpg::diag::dbg_FrameSamplerPhase = 0;

  // The sampler thread reports and flushes on its own schedule; give it up to 5 s.
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (std::chrono::steady_clock::now() < deadline &&
         !(Contains(lines.Lines(), "frame of") && Contains(lines.Lines(), "phase 1:"))) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  const std::vector<std::string> seen = lines.Lines();
  EXPECT_TRUE(Contains(seen, "frame of")) << "a 40 ms frame is over the 10 ms threshold";
  EXPECT_TRUE(Contains(seen, "phase 1:")) << "leaving phase 1 writes its stacks";

  std::ifstream in(folded);
  ASSERT_TRUE(in.good()) << folded.string();
  std::string first;
  std::getline(in, first);
  EXPECT_NE(first.find(' '), std::string::npos) << "a folded line is '<stack> <count>': " << first;
}
