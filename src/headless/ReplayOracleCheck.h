#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

#include "moho/sim/Sim.h"
#include "remote/SpatialOracle.h"

// Engine addition, server mode (plan WP4.1): headless's `--oracle-check`. The sim runs with the
// replay's `--focus` army as a lockstep client would; after every beat's `Sim::Sync` this
// asks the reference oracle (remote/VisibilityOracle.h) about every entity for that army and
// compares it with what the sim itself just did: whether the entity has its client-side
// interface (`Entity::mInterfaceCreated`) and, when both say published, the visibility mode.
// The oracle must agree without the focus, which is what lets the server ask it for every
// army while it runs unfocused.
//
// `--oracle-digests <file>` also writes, every beat, one line per army the oracle is asked
// about: "beat army entities visible digest", the digest over every entity's id, publication,
// mode, `CanViewSee` and `ViewShowsMesh`. Unfocused (-1) it asks about every army, as the server will; focused,
// about the focus army only. Each army's lines from an unfocused run must equal its lines from
// the run focused on it (scripts/server/oracle_digest_compare.py).
//
// Every beat it also builds the spatial oracle (remote/SpatialOracle.h, plan WPR.44) and checks
// that its set for each army it asks about (every army unfocused, the focus army otherwise)
// equals the brute-force set (plan WPR.54); a difference counts as a failure.

namespace faf::headless
{
  class CReplayOracleCheck final : public moho::CSyncObserver
  {
  public:
    /** `digestPath` empty: no digest file. */
    explicit CReplayOracleCheck(const std::string& digestPath);
    ~CReplayOracleCheck() override;

    /** The digest file could be opened (always true without one). */
    [[nodiscard]] bool IsOpen() const noexcept;

    /** Runs after every `Sim::Sync` from now on (one check at a time). */
    void Install();
    void Uninstall();

    [[nodiscard]] std::string Summary() const;
    /** Entity-beats where the oracle and the sim disagree (should stay 0). */
    [[nodiscard]] std::uint64_t Failures() const noexcept;

  private:
    enum EKind : std::size_t
    {
      kUnit,
      kBlip,
      kProp,
      kProjectile,
      kOther,
      kKindCount
    };

    struct SCounts
    {
      std::uint64_t checked = 0;
      std::uint64_t published = 0;     // published by the sim and by the oracle
      std::uint64_t onlyOracle = 0;    // the oracle publishes, the sim has no interface
      std::uint64_t onlySim = 0;       // the sim has an interface, the oracle does not publish
      std::uint64_t modeDiffers = 0;   // both published, different visibility mode
      std::uint64_t sent = 0;          // published by both and `CanViewSee` (the server sends it)
      std::uint64_t meshShown = 0;     // published by both and `ViewShowsMesh` (the client draws it)
    };

    void OnSyncWalkDone(moho::Sim& sim, const moho::SSyncData& packet) override;
    void WriteDigests(moho::Sim& sim, std::int32_t focusArmy);
    void CompareSpatial(moho::Sim& sim, std::int32_t focusArmy);

    mutable std::mutex mLock; // the sim's thread writes, the runner's reads the summary
    std::uint64_t mBeats = 0;
    std::int32_t mFocusArmy = -1;
    std::array<SCounts, kKindCount> mCounts{};
    std::vector<std::string> mExamples;
    std::FILE* mDigests = nullptr;
    remote::SpatialOracle mSpatial;
    std::vector<std::uint32_t> mBruteIds;
    std::vector<std::uint32_t> mSpatialIds;
    std::uint64_t mSpatialViews = 0;   // army-beats compared, brute force against spatial
    std::uint64_t mSpatialDiffers = 0; // of those, with a different set
    bool mDigestsWanted = false;
  };
} // namespace faf::headless
