#pragma once

#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "remote/wire/EntityFrame.h"
#include "remote/wire/OrdinalTable.h"

// Engine addition, server mode (faf-replay `--wire-stats`): the entities lane of the wire
// format run offline on a replay's sync packets. Each beat's entity state, as the sim
// published it to this run's focus, becomes a view frame; the frame is encoded against the
// previous one, decoded, and must come back equal (WPR.38 on recorded frames); the bytes are
// counted (a first offline measurement for WPR.6 and M0.2, entities lane only, no dead
// reckoning, one view).

namespace moho
{
  struct SSyncData;
}

namespace faf::replay
{
  class CReplayWireStats
  {
  public:
    /** `path`: one CSV line per beat; `mapSizeX/Z` fix the position quantiser. */
    CReplayWireStats(
      const std::string& path, const faf::remote::wire::SContentTables& tables, float mapSizeX, float mapSizeZ
    );
    ~CReplayWireStats();

    CReplayWireStats(const CReplayWireStats&) = delete;
    CReplayWireStats& operator=(const CReplayWireStats&) = delete;

    [[nodiscard]] bool IsOpen() const noexcept { return mFile != nullptr; }

    /** Applies one packet's entity lanes and measures the resulting frame. */
    void OnPacket(const moho::SSyncData& packet);

    /** One summary line for the run's output. */
    [[nodiscard]] std::string Summary() const;

  private:
    void Measure(std::uint32_t beat);

    std::FILE* mFile = nullptr;
    const faf::remote::wire::SContentTables& mTables;
    faf::remote::wire::SFrameCodec mCodec;
    std::map<std::uint32_t, faf::remote::wire::SEntityRecord> mWorld;
    faf::remote::wire::SViewFrame mPrevious;
    bool mHavePrevious = false;
    std::uint32_t mNextFrameId = 1;

    std::uint64_t mBeats = 0;
    std::uint64_t mDeltaBytes = 0;
    std::uint64_t mEntitySum = 0;
    std::uint32_t mMaxEntities = 0;
    std::uint64_t mUnknownBlueprints = 0;
    std::uint64_t mRoundTripFailures = 0;
    std::uint64_t mEncodeFailures = 0;
    std::vector<std::uint32_t> mDeltaSizes;
    std::uint64_t mFullBytesSum = 0;
    std::uint64_t mFullSamples = 0;
  };
} // namespace faf::replay
