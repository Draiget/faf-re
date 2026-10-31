#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "remote/ViewFrames.h"
#include "remote/wire/IntelGridDelta.h"

// Engine addition, server mode (plan WP5.2): headless's `--view-frames <file>`. Run unfocused (as
// the server runs), every beat it builds every army's frame (remote/ViewFrames.h) and writes one
// CSV line per army: entities in the frame, records the frame withheld, and the bytes of the
// frame encoded against that army's previous one (a lossless delta, no dead reckoning; plan
// WPR.6 measures the full channel). Each frame is decoded again and compared (a round trip
// that differs counts as a failure). It also measures the grid lane (plan WP5.4): the vision and
// water grids of the view's army and of every army that counts it as an ally, each as a
// run-length delta against the copy that view last received, decoded again and compared. And
// the entity frames once more with dead reckoning (plan WP7.5's 16-step scheme), each view's
// own reckoner and baseline, for the bytes a player would get (plan WPR.6; the CSV's last column).

namespace faf::headless
{
  class CReplayViewFrameStats final : public remote::CViewFrames
  {
  public:
    CReplayViewFrameStats(const std::string& path, const remote::wire::SContentTables& tables, float mapSizeX, float mapSizeZ);
    ~CReplayViewFrameStats() override;

    [[nodiscard]] bool IsOpen() const noexcept { return mFile != nullptr; }

    void Install();
    void Uninstall();

    [[nodiscard]] std::string Summary() const;
    /** Frames that did not encode, or decoded to another frame (should stay 0). */
    [[nodiscard]] std::uint64_t Failures() const noexcept { return mEncodeFailures + mRoundTripFailures + mGridFailures; }

  protected:
    void OnViewFrames(moho::Sim& sim) override;

  private:
    [[nodiscard]] std::uint32_t SendGrids(const moho::Sim& sim, std::size_t view);

    std::FILE* mFile = nullptr;
    remote::wire::SFrameCodec mCodec;
    remote::wire::SFrameCodec mReckonedCodec;
    std::vector<remote::CDeadReckoner> mReckoners;          // per army
    std::vector<remote::wire::SViewFrame> mPreviousReckoned; // per army
    std::vector<std::uint64_t> mReckonedBytes;               // per army, all beats
    // Records the reckoner anchored on the beat they were sent (new or re-anchored), per army: by
    // id family nibble, and the non-unit ones by blueprint ordinal (which entities the scheme fits badly).
    std::vector<std::array<std::uint64_t, 16>> mAnchoredByFamily;
    std::vector<std::unordered_map<std::uint32_t, std::uint64_t>> mAnchoredByBlueprint;
    const remote::wire::SContentTables* mTables = nullptr;
    std::vector<remote::wire::SViewFrame> mPrevious;
    std::vector<bool> mHavePrevious;
    std::vector<std::uint64_t> mBytes;    // per army, all beats
    std::vector<std::uint64_t> mEntities; // per army, all beats
    std::vector<std::uint64_t> mGridBytes; // per army, all beats
    std::map<std::tuple<std::size_t, std::size_t, int>, remote::wire::SGridBits> mSentGrids; // (view, army, kind)
    std::uint64_t mGridFailures = 0;
    std::uint64_t mBeats = 0;
    std::uint64_t mEncodeFailures = 0;
    std::uint64_t mRoundTripFailures = 0;
  };
} // namespace faf::headless
