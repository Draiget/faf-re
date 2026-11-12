#include "headless/ReplayEffectOps.h"

#include <atomic>

#include "moho/effects/rendering/EffectOps.h"

namespace faf::headless
{
  namespace
  {
    constexpr std::size_t kOps = static_cast<std::size_t>(moho::EEffectOp::Count);
    static_assert(kOps <= 32);

    // Emitters ending their lifetime destroy themselves on sim workers, so the counts are atomic.
    std::atomic<std::uint64_t> sCounts[kOps];

    void CountOp(
      const moho::EEffectOp op,
      const moho::IEffect*
    )
    {
      const auto index = static_cast<std::size_t>(op);
      if (index < kOps) {
        sCounts[index].fetch_add(1u, std::memory_order_relaxed);
      }
    }
  } // namespace

  bool CReplayEffectOps::Open(
    const std::string& path
  )
  {
    mFile = std::fopen(path.c_str(), "w");
    if (mFile == nullptr) {
      return false;
    }
    for (std::atomic<std::uint64_t>& count : sCounts) {
      count.store(0u, std::memory_order_relaxed);
    }
    std::fprintf(mFile, "beat total");
    for (std::size_t op = 0; op < kOps; ++op) {
      std::fprintf(mFile, " %s", moho::EffectOpName(static_cast<moho::EEffectOp>(op)));
    }
    std::fprintf(mFile, "\n");
    moho::gEffectOpHook = &CountOp;
    return true;
  }

  void CReplayEffectOps::OnBeat(
    const int beat
  )
  {
    if (mFile == nullptr) {
      return;
    }
    ++mBeats;
    std::uint64_t counts[kOps];
    std::uint64_t total = 0;
    for (std::size_t op = 0; op < kOps; ++op) {
      counts[op] = sCounts[op].exchange(0u, std::memory_order_relaxed);
      total += counts[op];
      mTotals[op] += counts[op];
      if (counts[op] > mMaxPerBeat[op]) {
        mMaxPerBeat[op] = counts[op];
      }
    }
    if (total == 0u) {
      return;
    }
    ++mBeatsWithOps;
    if (total > mBusiestBeatTotal) {
      mBusiestBeatTotal = total;
      mBusiestBeat = beat;
    }
    std::fprintf(mFile, "%d %llu", beat, static_cast<unsigned long long>(total));
    for (std::size_t op = 0; op < kOps; ++op) {
      std::fprintf(mFile, " %llu", static_cast<unsigned long long>(counts[op]));
    }
    std::fprintf(mFile, "\n");
  }

  void CReplayEffectOps::Finish(
    const char* const label
  )
  {
    if (mFile == nullptr) {
      return;
    }
    moho::gEffectOpHook = nullptr;
    std::fclose(mFile);
    mFile = nullptr;
    std::uint64_t all = 0;
    for (const std::uint64_t total : mTotals) {
      all += total;
    }
    std::printf(
      "[%s] effect ops: %llu in %d beats (%d with any), %.1f a beat, busiest beat %d with %llu\n",
      label,
      static_cast<unsigned long long>(all),
      mBeats,
      mBeatsWithOps,
      mBeats > 0 ? static_cast<double>(all) / mBeats : 0.0,
      mBusiestBeat,
      static_cast<unsigned long long>(mBusiestBeatTotal)
    );
    for (std::size_t op = 0; op < kOps; ++op) {
      if (mTotals[op] != 0u) {
        std::printf(
          "[%s]   %-26s %10llu  most in a beat %llu\n",
          label,
          moho::EffectOpName(static_cast<moho::EEffectOp>(op)),
          static_cast<unsigned long long>(mTotals[op]),
          static_cast<unsigned long long>(mMaxPerBeat[op])
        );
      }
    }
  }

  CReplayEffectOps::~CReplayEffectOps()
  {
    if (mFile != nullptr) {
      moho::gEffectOpHook = nullptr;
      std::fclose(mFile);
    }
  }
} // namespace faf::headless
