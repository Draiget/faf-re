#include "headless/ReplayEffectOps.h"

#include <algorithm>
#include <atomic>
#include <mutex>

#include "headless/EffectOpEncoder.h"
#include "moho/effects/rendering/EffectOps.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/entity/Entity.h"

namespace faf::headless
{
  namespace
  {
    constexpr std::size_t kOps = static_cast<std::size_t>(moho::EEffectOp::Count);
    static_assert(kOps <= 32);

    // The counts are atomic and the encoder behind a mutex: an op may come from a sim worker.
    std::atomic<std::uint64_t> sCounts[kOps];
    std::mutex sEncoderMutex;
    std::atomic<bool> sRecording{false};  // spares the copy and the lock when only counting
    CEffectOpEncoder* sEncoder = nullptr; // under sEncoderMutex

    /// The encoder takes floats: a curve becomes its bounds (min x, min y, max x, max y) and its keys (x, y, z each);
    /// a parameter beam its start, end, lifetime, width and texture scale, with its attachment, texture and blend mode.
    void Flatten(
      moho::SEffectOpArgs& args,
      std::vector<float>& floats
    )
    {
      if (const moho::SEfxCurve* const curve = args.curve; curve != nullptr) {
        floats = {curve->mBoundsMin.x, curve->mBoundsMin.y, curve->mBoundsMax.x, curve->mBoundsMax.y};
        for (const Wm3::Vector3f& key : curve->mKeys) {
          floats.insert(floats.end(), {key.x, key.y, key.z});
        }
        args.values = floats.data();
        args.valueCount = static_cast<std::uint32_t>(floats.size());
      }
      if (const moho::SCreateBeamParams* const beam = args.beam; beam != nullptr) {
        floats = {
          beam->mStart.x,
          beam->mStart.y,
          beam->mStart.z,
          beam->mEnd.x,
          beam->mEnd.y,
          beam->mEnd.z,
          beam->mLifetime,
          beam->mWidth,
          beam->mTextureScale
        };
        args.entity = moho::EffectOpEntity(beam->mAttachEntity);
        args.bone = beam->mAttachBoneIndex;
        args.army = beam->mAttachArmyIndex;
        args.texture = beam->mTexture.c_str();
        args.param = beam->mBlendMode;
        args.values = floats.data();
        args.valueCount = static_cast<std::uint32_t>(floats.size());
      }
    }

    void CountOp(
      const moho::EEffectOp op,
      const moho::SEffectOpArgs& args
    )
    {
      const auto index = static_cast<std::size_t>(op);
      if (index < kOps) {
        sCounts[index].fetch_add(1u, std::memory_order_relaxed);
      }
      if (!sRecording.load(std::memory_order_acquire)) {
        return;
      }
      moho::SEffectOpArgs flat = args;
      thread_local std::vector<float> floats;
      Flatten(flat, floats);
      const std::lock_guard<std::mutex> lock(sEncoderMutex);
      if (sEncoder != nullptr) {
        sEncoder->Record(op, flat);
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
      mEncoder = std::make_unique<CEffectOpEncoder>();
      const std::lock_guard<std::mutex> lock(sEncoderMutex);
      sEncoder = mEncoder.get();
      sRecording.store(true, std::memory_order_release);
    }
    for (std::atomic<std::uint64_t>& count : sCounts) {
      count.store(0u, std::memory_order_relaxed);
    }
    moho::gEffectOpHook = &CountOp;
    return true;
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

    if (mEncoder != nullptr) {
      CEffectOpEncoder::SBeat encoded;
      {
        const std::lock_guard<std::mutex> lock(sEncoderMutex);
        encoded = mEncoder->EndBeat();
      }
      mBeatBytes.push_back(encoded.bytes);
      mRecordedOps += encoded.ops;
      mRecordedBytes += encoded.bytes;
      if (encoded.ops != 0u) {
        std::fprintf(mRecordFile, "%d %u %u\n", beat, encoded.ops, encoded.bytes);
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
    {
      const std::lock_guard<std::mutex> lock(sEncoderMutex);
      sRecording.store(false, std::memory_order_release);
      sEncoder = nullptr;
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
    const CEffectOpEncoder::SBeat tail = mEncoder->EndBeat();
    mRecordedOps += tail.ops;
    mRecordedBytes += tail.bytes;
    if (!mBeatBytes.empty()) {
      mBeatBytes.back() += tail.bytes;
    }

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
      "created) %llu, blueprint names %zu, texture names %zu, effects still live %zu\n",
      label,
      static_cast<unsigned long long>(mEncoder->DerivedDestroys()),
      static_cast<unsigned long long>(mEncoder->Coalesced()),
      static_cast<unsigned long long>(mEncoder->DroppedTotal()),
      mEncoder->BlueprintNames(),
      mEncoder->TextureNames(),
      mEncoder->LiveEffects()
    );
    for (std::size_t op = 0; op < kOps; ++op) {
      const auto effectOp = static_cast<moho::EEffectOp>(op);
      const std::uint64_t ops = mEncoder->EncodedOps(effectOp);
      const std::uint64_t dropped = mEncoder->Dropped(effectOp);
      if (ops == 0u && dropped == 0u) {
        continue;
      }
      const std::uint64_t bytes = mEncoder->EncodedBytes(effectOp);
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
    mEncoder.reset();
  }

  CReplayEffectOps::~CReplayEffectOps()
  {
    if (mFile != nullptr || mRecordFile != nullptr) {
      moho::gEffectOpHook = nullptr;
      {
        const std::lock_guard<std::mutex> lock(sEncoderMutex);
        sRecording.store(false, std::memory_order_release);
        sEncoder = nullptr;
      }
    }
    if (mFile != nullptr) {
      std::fclose(mFile);
    }
    if (mRecordFile != nullptr) {
      std::fclose(mRecordFile);
    }
  }
} // namespace faf::headless
