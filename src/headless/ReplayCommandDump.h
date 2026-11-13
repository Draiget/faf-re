#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "remote/wire/CommandLane.h"

// Engine addition, server mode (plan WP5.14): headless's `--command-dump <file>` with `--view-bench --view-commands`.
// Per beat and unit, the command queues a client of one army holds: each id of the unit's command queue and build queue
// (`SSTIUnitVariableData::mCommands`, `mBuildQueue`) with the record of its helper, as `UserUnit:GetCommandQueue()` and
// the other user-side readers find it. Run twice on one replay:
//
// - lockstep (`--focus <army>`): the session's helpers kept from the sim's own beat packets, a lockstep client's;
// - the server-mode client (unfocused, as the server runs, `--command-dump-army <army>`): the helpers kept from that
//   army's view's command-records lane as its client applies it (wire/CommandLane.h `CCommandLaneReceiver`), every id
//   turned back into the sim's through the view's id map.
//
// Each file has a line per unit whenever its queues changed (and when it went), so the two must be equal line for line
// (the sim is the same at any focus, plan WPR.2); a line that differs names the unit, the beat and both queues.
//
// The model of the session is `CWldSession::DoBeat`'s use of the four lists: a descriptor makes a helper unless one
// with that id exists (`FindOrCreateCommandIssueHelper`), a packet replaces its data, a removal and a release delete
// it. A helper made again after it was deleted is a new one (a generation each), as the units' weak links to the old
// one go.

namespace faf::headless
{
  class CReplayCommandDump
  {
  public:
    struct SHelper
    {
      remote::wire::SCommandDescriptor descriptor;
      remote::wire::SCommandData data;
      std::uint64_t generation = 0;
    };

    CReplayCommandDump(const std::string& path, std::int32_t army, bool lockstep);
    ~CReplayCommandDump();
    CReplayCommandDump(const CReplayCommandDump&) = delete;
    CReplayCommandDump& operator=(const CReplayCommandDump&) = delete;

    [[nodiscard]] bool IsOpen() const noexcept
    {
      return mFile != nullptr;
    }
    [[nodiscard]] std::int32_t Army() const noexcept
    {
      return mArmy;
    }
    [[nodiscard]] bool Lockstep() const noexcept
    {
      return mLockstep;
    }

    /** One beat's four lists, in `DoBeat`'s order. Ids are the session's (the sim's, or the view client's). */
    void ApplyBeat(
      const std::vector<remote::wire::SCommandDescriptor>& descriptors,
      const std::vector<std::pair<std::uint32_t, remote::wire::SCommandData>>& updates,
      const std::vector<std::uint32_t>& removals,
      const std::vector<std::uint32_t>& releases
    );
    [[nodiscard]] const SHelper* Find(
      const std::uint32_t id
    ) const noexcept
    {
      const auto found = mHelpers.find(id);
      return found != mHelpers.end() ? &found->second : nullptr;
    }

    /** A unit's queues at `beat` as text; written when they differ from its last. */
    void Unit(std::uint32_t beat, std::uint32_t unit, std::string text);
    /** The beat is over: units written before and not this beat are gone. */
    void EndBeat(std::uint32_t beat);

    /** One queue entry as text: the sim's command id, its helper's record (`?` for none), targets as given. */
    [[nodiscard]] static std::string
    Entry(std::uint32_t simCommand, const SHelper* helper, const std::string& target1, const std::string& target2);
    /** A target as text, its entity as `entity` says it (the sim's id, `none`, or a server-mode client's note). */
    [[nodiscard]] static std::string Target(const remote::wire::SCommandTarget& target, const std::string& entity);

    [[nodiscard]] std::string Summary() const;

  private:
    std::FILE* mFile = nullptr;
    std::int32_t mArmy;
    bool mLockstep;
    std::unordered_map<std::uint32_t, SHelper> mHelpers;
    std::uint64_t mGenerations = 0;
    std::unordered_map<std::uint32_t, std::uint64_t> mUnitHash; // the last text's hash per unit
    std::unordered_map<std::uint32_t, std::uint32_t> mUnitSeen; // the beat each was last given
    std::uint64_t mLines = 0;
    std::uint64_t mBeats = 0;
    std::uint64_t mUpdatesWithoutHelper = 0; // the session would dereference a null helper
    std::uint64_t mRemovalsWithoutHelper = 0;
    std::uint64_t mEntries = 0;        // queue entries written
    std::uint64_t mMissingEntries = 0; // of them with no helper
  };
} // namespace faf::headless
