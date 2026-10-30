#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "remote/BeatChangeSet.h"

// Engine addition, server mode (plan WP5.1): headless's `--changeset-check`. Every beat it checks
// the change set (remote/BeatChangeSet.h) against the packet `Sim::Sync` built in the same walk:
// every entity id the packet carries (creations, entity and unit updates, deletes, erases) must
// be in the change set, or a view built from the change set would miss what the lockstep client
// receives. Change-set entities the packet does not carry are counted by kind, apart for those
// the focus army's view publishes (which the packet should have carried: a failure too).

namespace faf::headless
{
  class CReplayChangeSetCheck final : public remote::CBeatChangeSet
  {
  public:
    CReplayChangeSetCheck() = default;
    ~CReplayChangeSetCheck() override;

    /** Observes `Sim::Sync` from now on (one observer at a time). */
    void Install();
    void Uninstall();

    [[nodiscard]] std::string Summary() const;
    /** Packet ids missing from the change set, and published entities the packet lacks (should stay 0). */
    [[nodiscard]] std::uint64_t Failures() const noexcept;

  protected:
    void OnBeatChanges(moho::Sim& sim, const moho::SSyncData& packet) override;

  private:
    static constexpr std::size_t kKindCount = 5; // unit, blip, prop, projectile, other

    mutable std::mutex mLock; // the sim's thread writes, the runner's reads the summary
    std::vector<std::uint32_t> mIds;
    std::vector<std::uint32_t> mPacketIds;
    std::uint64_t mBeats = 0;
    std::uint64_t mChanged = 0;           // change-set entities, all beats
    std::uint64_t mPacketRecords = 0;     // distinct packet ids, all beats
    std::uint64_t mPacketNotInSet = 0;    // failure
    std::uint64_t mPublishedSilent = 0;   // failure: the view publishes it, the packet has no record
    std::array<std::uint64_t, kKindCount> mUnpublishedByKind{}; // in the set, not published at this focus
    std::vector<std::string> mExamples;
  };
} // namespace faf::headless
