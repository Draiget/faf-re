#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace faf::headless
{
  /**
   * Plan WP9.1: `--effect-ops <file>` counts the sim's effect operations (moho/effects/rendering/EffectOps.h) per
   * beat, to size what replicating them would send. The file gets one line per beat with any: `beat total` and each
   * op's count by name; the run ends with each op's total, its most in one beat, and the busiest beat's total.
   * The ops of a beat are read when its packet arrives (the sim may already be a beat ahead), so a count can land a
   * beat late; totals are exact.
   */
  class CReplayEffectOps
  {
  public:
    /** Installs the counting hook; false when the file can't be written. */
    [[nodiscard]] bool Open(const std::string& path);
    void OnBeat(int beat);
    /** Removes the hook, closes the file and prints the summary with `label`. */
    void Finish(const char* label);
    ~CReplayEffectOps();

  private:
    std::FILE* mFile = nullptr;
    std::uint64_t mTotals[32]{};
    std::uint64_t mMaxPerBeat[32]{};
    std::uint64_t mBusiestBeatTotal = 0;
    int mBusiestBeat = -1;
    int mBeatsWithOps = 0;
    int mBeats = 0;
  };
} // namespace faf::headless
