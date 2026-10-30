#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

// Engine addition, server mode (plan WP4.1): headless's `--oracle-check`. The sim runs with the
// replay's `--focus` army as a lockstep client would; after every beat's `Sim::Sync` this
// asks the reference oracle (remote/VisibilityOracle.h) about every entity for that army and
// compares it with what the sim itself just did: whether the entity has its client-side
// interface (`Entity::mInterfaceCreated`) and, when both say published, the visibility mode.
// The oracle must agree without the focus, which is what lets the server ask it for every
// army while it runs unfocused.

namespace moho
{
  class Sim;
}

namespace faf::headless
{
  class CReplayOracleCheck
  {
  public:
    CReplayOracleCheck() = default;
    ~CReplayOracleCheck();

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
      std::uint64_t reconGrid = 0;     // published in mode ReconGrid
      std::uint64_t reconGridSeen = 0; // of those, inside the view's sight (the grid test)
    };

    static void Observe(moho::Sim& sim, void* context);
    void OnSync(moho::Sim& sim);

    mutable std::mutex mLock; // the sim's thread writes, the runner's reads the summary
    std::uint64_t mBeats = 0;
    std::int32_t mFocusArmy = -1;
    std::array<SCounts, kKindCount> mCounts{};
    std::vector<std::string> mExamples;
  };
} // namespace faf::headless
