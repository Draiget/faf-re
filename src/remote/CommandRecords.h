#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>

#include "remote/wire/CommandLane.h"

namespace moho
{
  struct REntityBlueprint;
  struct SSTICommandConstantData;
  struct SSTICommandVariableData;
  struct SSyncData;
} // namespace moho

// Engine addition, server mode (plan WP5.14, §6 "Command events: units known to `a`"): each view's command-records lane
// (remote/wire/CommandLane.h). A lockstep client focused on army `a` gets, each beat, the records of the commands that
// hold a unit its sim publishes to it: `CUnitCommand::RefreshPublishedCommandEvent` (0x006E8DC0) lists a command's
// units whose `mVisibilityHidden` is set, and `Unit::UpdateVisibility` (0x006ABC30) sets that only for the focus army's
// units (every unit with focus -1). A command whose list is empty is not shown (a removal when it was); one that comes
// to have units is described again.
//
// The server's sim runs unfocused, so its beat packet lists every shown unit of every command. `CCommandBook` keeps,
// on the sim thread, each command the sim published and the beat's records in the sim's order; each view's
// `CCommandViewRoute` replays them as the focused sim would have published them: each record's units cut to the view's
// army (every unit for a player watching everything), a descriptor the first time a command has one of them, a removal
// when it has none left, the sim's releases for the commands the view was given (and every release of its own
// commands, whose ids its client's pool takes back). The two lists then differ from a focused sim's only where the
// sim's choice of what to publish differs, which it doesn't (the sim is the same at any focus, plan WPR.2).
//
// A view that comes back holding nothing (`whole`) gets every shown command with a unit of its army, described whole,
// and its client lets go of any other it held.

namespace faf::remote
{
  /** Every command the sim published, as the server keeps it; written on the sim thread once a beat. */
  class CCommandBook
  {
  public:
    struct SCommand
    {
      wire::SCommandDescriptor descriptor; // the sim's id; blueprint as the content tables' ordinal + 1
      wire::SCommandData data;             // as last published: every shown unit, the sim's entity ids
      std::vector<std::uint8_t> armies;    // per unit of `data.units`: its army (kNoArmy: not found)
      bool shown = false;                  // the sim's `mHasPublishedCommandEvent`, as its records say
    };
    enum class EEvent : std::uint8_t
    {
      Update,  // a published packet (after its descriptor, when it had one)
      Removal, // no longer shown
      Release, // the sim let go of it
    };
    struct SEvent
    {
      EEvent kind;
      std::uint32_t id;
    };
    static constexpr std::uint8_t kNoArmy = 0xFFu;

    /** The army of a unit by its sim id (kNoArmy when there's none). */
    using ArmyOf = std::function<std::uint8_t(std::uint32_t unit)>;
    /** A blueprint as the lane names it: 0 none, else the content tables' ordinal + 1. */
    using BlueprintRef = std::function<std::uint32_t(const moho::REntityBlueprint* blueprint)>;

    /**
     * The beat's command records from the sim's packet, after `CCommandDB::PublishSyncData`. Last beat's released
     * commands are forgotten first: the views read this beat's events until the next call.
     */
    void TakeBeat(const moho::SSyncData& packet, const ArmyOf& armyOf, const BlueprintRef& blueprint);

    /** This beat's events, in the order a session's beat applies them (updates, removals, releases). */
    [[nodiscard]] const std::vector<SEvent>& Events() const noexcept
    {
      return mEvents;
    }
    [[nodiscard]] const SCommand* Find(
      const std::uint32_t id
    ) const noexcept
    {
      const auto found = mCommands.find(id);
      return found != mCommands.end() ? &found->second : nullptr;
    }
    /** The live commands' ids, ascending (released ones of this beat left out). */
    [[nodiscard]] const std::vector<std::uint32_t>& LiveIds() const noexcept
    {
      return mLiveIds;
    }
    [[nodiscard]] std::size_t Live() const noexcept
    {
      return mLiveIds.size();
    }
    /** Beats taken, and records taken over all of them. */
    [[nodiscard]] std::uint64_t Beats() const noexcept
    {
      return mBeats;
    }
    [[nodiscard]] std::uint64_t Descriptors() const noexcept
    {
      return mDescriptors;
    }
    [[nodiscard]] std::uint64_t Packets() const noexcept
    {
      return mPackets;
    }
    [[nodiscard]] std::uint64_t Removals() const noexcept
    {
      return mRemovals;
    }
    [[nodiscard]] std::uint64_t Releases() const noexcept
    {
      return mReleases;
    }
    /** Packets for a command the book had no descriptor of (should stay 0), units of no army found. */
    [[nodiscard]] std::uint64_t Orphans() const noexcept
    {
      return mOrphans;
    }
    [[nodiscard]] std::uint64_t UnitsWithoutArmy() const noexcept
    {
      return mUnitsWithoutArmy;
    }

  private:
    std::unordered_map<std::uint32_t, SCommand> mCommands;
    std::vector<SEvent> mEvents;
    std::vector<std::uint32_t> mReleased; // erased at the next `TakeBeat`
    std::vector<std::uint32_t> mLiveIds;
    std::uint64_t mBeats = 0;
    std::uint64_t mDescriptors = 0;
    std::uint64_t mPackets = 0;
    std::uint64_t mRemovals = 0;
    std::uint64_t mReleases = 0;
    std::uint64_t mOrphans = 0;
    std::uint64_t mUnitsWithoutArmy = 0;
  };

  /** A sim's command record as the lane has it (the sim's ids). */
  [[nodiscard]] wire::SCommandData CommandDataFromSim(const moho::SSTICommandVariableData& data);
  /** A sim's command descriptor as the lane has it (the sim's id); `blueprint` names its blueprint. */
  [[nodiscard]] wire::SCommandDescriptor
  CommandDescriptorFromSim(const moho::SSTICommandConstantData& data, const CCommandBook::BlueprintRef& blueprint);

  /** What one view's client holds of the book, and the lane that keeps it so; used from one thread at a time. */
  class CCommandViewRoute
  {
  public:
    /** The view's own ids (remote/ViewIdMap.h), on the view's own thread. */
    struct STranslate
    {
      std::function<std::uint32_t(std::uint32_t simCommand)> command; // its view id, handed out the first time
      std::function<bool(std::uint32_t simCommand)> isOwn;            // one of the view's command sources
      std::function<std::uint32_t(std::uint32_t simEntity)> entity;   // its view id, or kNoCommandEntity
    };

    /**
     * The view's lane for the book's beat. `army`: the view's army, whose units it is shown; `everything`: every unit
     * (a player watching everything, as focus -1). `whole`: its client holds nothing (it came back), so every shown
     * command with one of its units goes whole, and the lane says so.
     */
    void Write(
      const CCommandBook& book,
      std::int32_t army,
      bool everything,
      bool whole,
      const STranslate& translate,
      wire::SCommandLane& lane
    );

    /** Commands its client holds a helper of now. */
    [[nodiscard]] std::size_t Shown() const noexcept;

    struct SCounts
    {
      std::uint64_t descriptors = 0;
      std::uint64_t updates = 0;
      std::uint64_t emptyUpdates = 0; // updates that changed no field
      std::uint64_t removals = 0;
      std::uint64_t releases = 0;
      std::uint64_t ownReleases = 0; // releases of its own commands it was never shown
      std::uint64_t wholes = 0;
      std::uint64_t unitsLeftOut = 0;      // units of other armies in the sim's records, not sent
      std::uint64_t targetsWithheld = 0;   // target entities it holds no record of, sent as none
      std::uint64_t targetsRenumbered = 0; // target entities sent under the view's own id
    };
    [[nodiscard]] const SCounts& Counts() const noexcept
    {
      return mCounts;
    }

  private:
    /** The record as the view gets it: its units, targets in its ids. */
    void Cut(
      const CCommandBook::SCommand& command,
      std::int32_t army,
      bool everything,
      const STranslate& translate,
      wire::SCommandData& out
    );

    struct SHeld
    {
      std::uint32_t viewId = 0;
      bool shown = false;      // its client holds a helper (descriptor sent, no removal since)
      wire::SCommandData sent; // what its client holds of the data
    };
    std::unordered_map<std::uint32_t, SHeld> mHeld; // by sim id: every command it was given and not yet released
    SCounts mCounts;
  };
} // namespace faf::remote
