#pragma once

#include <cstdint>
#include <array>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "remote/FrameBuilder.h"
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
    void AccountFieldBits(const faf::remote::wire::SFrameDelta& delta);

    std::FILE* mFile = nullptr;
    const faf::remote::wire::SContentTables& mTables;
    faf::remote::wire::SFrameCodec mCodec;
    faf::remote::CViewFrameBuilder mBuilder;
    faf::remote::wire::SViewFrame mPrevious;
    // The same frames without the yaw form and without the unit block, for comparison.
    faf::remote::wire::SViewFrame mPreviousNoYaw;
    faf::remote::wire::SViewFrame mPreviousNoUnits;
    std::uint64_t mDeltaBytesNoYaw = 0;
    std::uint64_t mDeltaBytesNoUnits = 0;
    std::uint64_t mYawOnlyRecords = 0;
    std::uint64_t mUnitRecords = 0;
    /** The same frames dead-reckoned (WP7.5) at one tolerance, with their own state and baseline. */
    struct SDeadReckoningVariant
    {
      faf::remote::CDeadReckoner reckoner;
      faf::remote::wire::SViewFrame previous;
      std::uint64_t bytes = 0;
    };
    SDeadReckoningVariant mDeadReckoning[2]{{faf::remote::CDeadReckoner(4)}, {faf::remote::CDeadReckoner(16)}}; // 1/16, 1/4 unit
    faf::remote::wire::SFrameCodec mDeadReckoningCodec;

    /** Bits of changed records by field class, summed over the run (creations and ids apart). */
    struct SFieldBits
    {
      std::uint64_t transform = 0;  // position, orientation
      std::uint64_t orientation = 0; // the orientation part of `transform`
      std::uint64_t scalars = 0;    // health, max health, build progress
      std::uint64_t flags = 0;      // entity flags, kind, blueprint, army
      std::uint64_t unit = 0;       // unit block
      /** Appearance block: mesh, scale, attachments, visual flags, impact, scroll, intel radii. */
      std::array<std::uint64_t, 7> appearance{};
      /** Unit block beyond the basics: stats tree, constants, detail ids, economy, queues, weapons, attributes. */
      std::array<std::uint64_t, 7> unitParts{};
      std::uint64_t overhead = 0;   // id gaps and masks of changed records
      std::uint64_t creations = 0;  // whole created records with their ids
      std::uint64_t removals = 0;   // removed ids
    } mFieldBits;
    std::array<std::uint64_t, 7> mCreationAppearanceBits{}; // the appearance part of `creations`
    bool mHavePrevious = false;

    std::uint64_t mBeats = 0;
    std::uint64_t mDeltaBytes = 0;
    std::uint64_t mEntitySum = 0;
    std::uint32_t mMaxEntities = 0;
    std::uint64_t mRoundTripFailures = 0;
    std::uint64_t mEncodeFailures = 0;
    std::vector<std::uint32_t> mDeltaSizes;
    std::uint64_t mFullBytesSum = 0;
    std::uint64_t mFullSamples = 0;
  };
} // namespace faf::replay
