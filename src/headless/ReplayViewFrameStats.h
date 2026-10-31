#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <map>
#include <random>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "remote/FrameWindow.h"
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
// With `--view-ids` the frames carry each view's own ids (plan WP5.9, remote/ViewIdMap.h), and
// every renumbered id in them must map back to a sim id of the same family and source. With
// `--view-loss <percent>` (and `--view-ack-delay <beats>`) every view's frames also go through a
// simulated lossy channel (plan WP5.3, remote/FrameWindow.h): each frame is encoded against the
// newest frame the client acknowledged, a seeded share of frames is lost, the client acknowledges
// its newest decoded frame and the acknowledgement reaches the server that many beats later.
// Every frame that arrives must decode to the frame sent. With `--spy` (plan WP16.3) every view's
// decoded frame, what its client holds, is checked against the sim each beat: every record must
// be one the oracle lets that view have (`ResolveViewVisibility` publishes it and `CanViewSee`
// passes; a record the sim no longer has is an orphan, WP7.7), and every entity a record names
// (attachment parent and children, a unit's creator, selection inheritor, focus, guarded unit and
// target blip) must be one the client holds. Each miss is a violation, counted by kind.

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
    [[nodiscard]] std::uint64_t Failures() const noexcept
    {
      std::uint64_t unheld = 0;
      for (const std::uint64_t count : mSpyUnheld) {
        unheld += count;
      }
      return mEncodeFailures + mRoundTripFailures + mGridFailures + mIdFailures + mChannelFailures + mSpyOutside + unheld;
    }

    /** The spy client's checks (`--spy`). */
    void EnableSpy() noexcept { mSpyOn = true; }

    /** The simulated channel (`--view-loss`, `--view-ack-delay`); off at 0 % loss and 0 beats. */
    void SetChannel(std::uint32_t lossPercent, std::uint32_t ackDelayBeats) noexcept
    {
      mLossPercent = lossPercent;
      mAckDelay = ackDelayBeats;
      mChannelOn = lossPercent != 0u || ackDelayBeats != 0u;
    }

  protected:
    void OnViewFrames(moho::Sim& sim) override;

  private:
    [[nodiscard]] std::uint32_t SendGrids(const moho::Sim& sim, std::size_t view);
    void CheckIds(const remote::wire::SViewFrame& frame, const remote::CViewIdMap& map);
    void SendOverChannel(std::size_t army, const remote::wire::SViewFrame& frame, std::uint32_t beat);
    void Spy(const moho::Sim& sim, std::size_t army, const remote::wire::SViewFrame& held);

    /** One view's simulated channel. */
    struct SChannel
    {
      remote::CServerFrameWindow server;
      remote::CClientFrameWindow client;
      std::mt19937 random;
      std::deque<std::pair<std::uint32_t, std::uint32_t>> acks; // (beat it arrives, frame id)
      std::uint64_t bytes = 0;
      std::uint64_t lost = 0;
    };

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
    bool mChannelOn = false;
    std::uint32_t mLossPercent = 0;
    std::uint32_t mAckDelay = 0;
    std::vector<SChannel> mChannels; // per army
    std::uint64_t mChannelFailures = 0; // frames that arrived and did not decode to the frame sent
    bool mSpyOn = false;
    std::uint64_t mSpyRecords = 0;
    std::uint64_t mSpyOutside = 0;  // records the oracle does not let the view have
    std::uint64_t mSpyOrphans = 0;  // records the sim no longer has
    std::uint64_t mSpyReferences = 0;
    std::array<std::uint64_t, 7> mSpyUnheld{}; // by field: names an entity the client does not hold
    std::vector<std::string> mSpyExamples;
    std::uint64_t mIdsChecked = 0; // renumbered ids found in the frames (with `--view-ids`)
    std::uint64_t mIdFailures = 0; // of those, ids that do not map back to a sim id of their family and source
  };
} // namespace faf::headless
