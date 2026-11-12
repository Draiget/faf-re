#include "headless/ReplayEffectOps.h"

#include <algorithm>
#include <atomic>

#include "moho/effects/rendering/EffectOps.h"
#include "server/EffectOpEncoder.h"
#include "server/EffectOpRecorder.h"

namespace faf::headless
{
  namespace
  {
    constexpr std::size_t kOps = static_cast<std::size_t>(moho::EEffectOp::Count);
    static_assert(kOps <= 32);

    // The counts are atomic: an op may come from a sim worker. The recorder locks for itself.
    std::atomic<std::uint64_t> sCounts[kOps];
    std::atomic<bool> sRecording{false}; // spares the recorder's work when only counting

    void CountOp(
      const moho::EEffectOp op,
      const moho::SEffectOpArgs& args
    )
    {
      const auto index = static_cast<std::size_t>(op);
      if (index < kOps) {
        sCounts[index].fetch_add(1u, std::memory_order_relaxed);
      }
      if (sRecording.load(std::memory_order_acquire)) {
        server::CEffectOpRecorder::Hook(op, args);
      }
    }

    /** The value at `fraction` of the sorted `values` (nearest rank). */
    [[nodiscard]] std::uint32_t Percentile(
      const std::vector<std::uint32_t>& sorted,
      const double fraction
    )
    {
      if (sorted.empty()) {
        return 0u;
      }
      const auto rank = static_cast<std::size_t>(fraction * static_cast<double>(sorted.size() - 1u) + 0.5);
      return sorted[std::min(rank, sorted.size() - 1u)];
    }
  } // namespace

  CReplayEffectOps::CReplayEffectOps() = default;

  bool CReplayEffectOps::Open(
    const std::string& countsPath,
    const std::string& recordPath,
    std::string& error
  )
  {
    if (countsPath.empty() && recordPath.empty()) {
      return true;
    }
    if (!countsPath.empty()) {
      mFile = std::fopen(countsPath.c_str(), "w");
      if (mFile == nullptr) {
        error = "cannot write " + countsPath;
        return false;
      }
      std::fprintf(mFile, "beat total");
      for (std::size_t op = 0; op < kOps; ++op) {
        std::fprintf(mFile, " %s", moho::EffectOpName(static_cast<moho::EEffectOp>(op)));
      }
      std::fprintf(mFile, "\n");
    }
    if (!recordPath.empty()) {
      mRecordFile = std::fopen(recordPath.c_str(), "w");
      if (mRecordFile == nullptr) {
        error = "cannot write " + recordPath;
        return false;
      }
      std::fprintf(mRecordFile, "beat ops bytes\n");
      mRecorder = std::make_unique<server::CEffectOpRecorder>();
      mNames = std::make_unique<server::CEffectLaneNames>();
      mRecorder->Attach();
      sRecording.store(true, std::memory_order_release);
    }
    for (std::atomic<std::uint64_t>& count : sCounts) {
      count.store(0u, std::memory_order_relaxed);
    }
    moho::gEffectOpHook = &CountOp;
    return true;
  }

  std::pair<std::uint32_t, std::uint32_t> CReplayEffectOps::TakeLane()
  {
    const server::SEffectBeat beat = mRecorder->EndBeat();
    mNames->Write(beat, mLane);
    return {beat.opCount, static_cast<std::uint32_t>(mLane.size())};
  }

  void CReplayEffectOps::OnBeat(
    const int beat
  )
  {
    if (mFile == nullptr && mRecordFile == nullptr) {
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
    if (total != 0u) {
      ++mBeatsWithOps;
      if (total > mBusiestBeatTotal) {
        mBusiestBeatTotal = total;
        mBusiestBeat = beat;
      }
    }
    if (mFile != nullptr && total != 0u) {
      std::fprintf(mFile, "%d %llu", beat, static_cast<unsigned long long>(total));
      for (std::size_t op = 0; op < kOps; ++op) {
        std::fprintf(mFile, " %llu", static_cast<unsigned long long>(counts[op]));
      }
      std::fprintf(mFile, "\n");
    }

    if (mRecorder != nullptr) {
      const auto [ops, bytes] = TakeLane();
      mBeatBytes.push_back(bytes);
      mRecordedOps += ops;
      mRecordedBytes += bytes;
      if (ops != 0u) {
        std::fprintf(mRecordFile, "%d %u %u\n", beat, ops, bytes);
      }
    }
  }

  void CReplayEffectOps::Finish(
    const char* const label
  )
  {
    if (mFile == nullptr && mRecordFile == nullptr) {
      return;
    }
    moho::gEffectOpHook = nullptr;
    sRecording.store(false, std::memory_order_release);
    if (mRecorder != nullptr) {
      mRecorder->Detach();
    }
    if (mFile != nullptr) {
      std::fclose(mFile);
      mFile = nullptr;
    }
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
    FinishRecord(label);
  }

  void CReplayEffectOps::FinishRecord(
    const char* const label
  )
  {
    if (mRecordFile == nullptr) {
      return;
    }
    std::fclose(mRecordFile);
    mRecordFile = nullptr;
    // Ops of the last beat arrive after its packet; encode them with it.
    const auto [tailOps, tailBytes] = TakeLane();
    mRecordedOps += tailOps;
    mRecordedBytes += tailBytes;
    if (!mBeatBytes.empty()) {
      mBeatBytes.back() += tailBytes;
    }

    const server::CEffectOpEncoder& encoder = mRecorder->Encoder();
    std::vector<std::uint32_t> sorted = mBeatBytes;
    std::sort(sorted.begin(), sorted.end());
    const double mean = sorted.empty() ? 0.0 : static_cast<double>(mRecordedBytes) / static_cast<double>(sorted.size());
    std::printf(
      "[%s] effect record: %llu ops encoded, %llu bytes (%.1f KB) in %zu beats; a beat mean %.1f p50 %u p95 %u p99 %u "
      "max %u bytes; %.2f KB/s at 10 beats a second\n",
      label,
      static_cast<unsigned long long>(mRecordedOps),
      static_cast<unsigned long long>(mRecordedBytes),
      static_cast<double>(mRecordedBytes) / 1024.0,
      sorted.size(),
      mean,
      Percentile(sorted, 0.50),
      Percentile(sorted, 0.95),
      Percentile(sorted, 0.99),
      sorted.empty() ? 0u : sorted.back(),
      mean * 10.0 / 1024.0
    );
    std::printf(
      "[%s] effect record: derived destroys left out %llu, coalesced SetFloat %llu, dropped (effect never seen "
      "created) %llu, blueprint names %zu, texture names %zu, names sent %llu, effects still live %zu\n",
      label,
      static_cast<unsigned long long>(encoder.DerivedDestroys()),
      static_cast<unsigned long long>(encoder.Coalesced()),
      static_cast<unsigned long long>(encoder.DroppedTotal()),
      encoder.BlueprintNames(),
      encoder.TextureNames(),
      static_cast<unsigned long long>(mNames->NamesSent()),
      encoder.LiveEffects()
    );
    for (std::size_t op = 0; op < kOps; ++op) {
      const auto effectOp = static_cast<moho::EEffectOp>(op);
      const std::uint64_t ops = encoder.EncodedOps(effectOp);
      const std::uint64_t dropped = encoder.Dropped(effectOp);
      if (ops == 0u && dropped == 0u) {
        continue;
      }
      const std::uint64_t bytes = encoder.EncodedBytes(effectOp);
      std::printf(
        "[%s]   record %-26s %10llu ops %12llu bytes %6.2f a op  dropped %llu\n",
        label,
        moho::EffectOpName(effectOp),
        static_cast<unsigned long long>(ops),
        static_cast<unsigned long long>(bytes),
        ops != 0u ? static_cast<double>(bytes) / static_cast<double>(ops) : 0.0,
        static_cast<unsigned long long>(dropped)
      );
    }
    mRecorder.reset();
    mNames.reset();
  }

  CReplayEffectOps::~CReplayEffectOps()
  {
    if (mFile != nullptr || mRecordFile != nullptr) {
      moho::gEffectOpHook = nullptr;
      sRecording.store(false, std::memory_order_release);
    }
    mRecorder.reset(); // detaches
    if (mFile != nullptr) {
      std::fclose(mFile);
    }
    if (mRecordFile != nullptr) {
      std::fclose(mRecordFile);
    }
  }
} // namespace faf::headless
