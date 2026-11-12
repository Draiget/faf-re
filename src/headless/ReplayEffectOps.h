#pragma once

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

namespace faf::headless
{
  class CEffectOpEncoder;

  /**
   * Plan WP9.1: `--effect-ops <file>` counts the sim's effect operations (moho/effects/rendering/EffectOps.h) per
   * beat, to size what replicating them would send. The file gets one line per beat with any: `beat total` and each
   * op's count by name; the run ends with each op's total, its most in one beat, and the busiest beat's total.
   *
   * `--effect-record <file>` (step 2) also encodes them as the server would send them (EffectOpEncoder.h): one line
   * per beat with any, `beat ops bytes`; the run ends with the total, bytes a beat (mean, p50, p95, p99, max over
   * every beat), KB/s at 10 beats a second, bytes per op type, the ops dropped (effect never seen created), the
   * derived destroys left out and the name tables' sizes.
   *
   * The ops of a beat are read when its packet arrives (the sim may already be a beat ahead), so an op can land a
   * beat late; totals are exact.
   */
  class CReplayEffectOps
  {
  public:
    CReplayEffectOps();
    ~CReplayEffectOps();

    /** Installs the hook; either path may be empty. False (and `error` set) when a file can't be written. */
    [[nodiscard]] bool Open(const std::string& countsPath, const std::string& recordPath, std::string& error);
    void OnBeat(int beat);
    /** Removes the hook, closes the files and prints the summaries with `label`. */
    void Finish(const char* label);

  private:
    void FinishRecord(const char* label);

    std::FILE* mFile = nullptr;
    std::uint64_t mTotals[32]{};
    std::uint64_t mMaxPerBeat[32]{};
    std::uint64_t mBusiestBeatTotal = 0;
    int mBusiestBeat = -1;
    int mBeatsWithOps = 0;
    int mBeats = 0;

    std::FILE* mRecordFile = nullptr;
    std::unique_ptr<CEffectOpEncoder> mEncoder;
    std::vector<std::uint32_t> mBeatBytes; // every beat's encoded bytes, for the percentiles
    std::uint64_t mRecordedOps = 0;
    std::uint64_t mRecordedBytes = 0;
  };
} // namespace faf::headless
