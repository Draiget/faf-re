#pragma once

#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "moho/render/camera/VTransform.h"

// Engine addition, server mode (headless `--bone-stats`, plan M0.3): how many bones of each
// unit change from one beat to the next, per blueprint. The sim publishes each unit's pose for
// the beat (a fresh `CAniPose` every tick, `CAniActor::UpdateManipulators`); this compares its
// bones' local transforms with the same unit's previous beat, exactly and beyond a small
// tolerance, the input to the pose budget (§7.2 bone delta, WP8).

namespace moho
{
  struct SSyncData;
}

namespace faf::headless
{
  class CReplayBoneStats
  {
  public:
    /** `path`: per-beat CSV; `path` + ".blueprints.csv": per-blueprint totals at the end. */
    explicit CReplayBoneStats(const std::string& path);
    ~CReplayBoneStats();

    CReplayBoneStats(const CReplayBoneStats&) = delete;
    CReplayBoneStats& operator=(const CReplayBoneStats&) = delete;

    [[nodiscard]] bool IsOpen() const noexcept { return mFile != nullptr; }

    void OnPacket(const moho::SSyncData& packet);

    /** Writes the per-blueprint file and returns one summary line. */
    [[nodiscard]] std::string Finish();

  private:
    struct SUnitPose
    {
      std::string blueprint;
      std::vector<moho::VTransform> bones;
    };

    struct SBlueprintTotals
    {
      std::uint64_t unitBeats = 0;
      std::uint64_t bones = 0;
      std::uint64_t changedExact = 0;
      std::uint64_t changedOverTolerance = 0;
      std::uint32_t maxChanged = 0;
    };

    std::FILE* mFile = nullptr;
    std::string mPath;
    std::map<std::uint32_t, SUnitPose> mUnits;
    std::map<std::string, SBlueprintTotals> mBlueprints;
    std::vector<std::uint32_t> mChangedPerBeat;
    std::uint64_t mBeats = 0;
  };
} // namespace faf::headless
