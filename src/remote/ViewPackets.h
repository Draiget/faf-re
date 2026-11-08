#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

#include "gpg/core/containers/ChunkedVector.h"
#include "gpg/core/containers/FlatGenerationMap.h"
#include "remote/BeatChangeSet.h"
#include "remote/FrameBuilder.h"
#include "remote/VisibilityOracle.h"

// Engine addition, server mode (plan WP5.2): the entity lanes of the packet a lockstep client
// focused on each army would receive, rebuilt from the unfocused sim's change set without
// writing the sim. For every entity the walk synced and every army it replays what `Sim::Sync`
// would have done under that focus:
//
//   - publication from the visibility oracle (`ResolveViewVisibility`, the three
//     `UpdateVisibility` overrides); `Prop::Sync` (0x006FA2A0) publishes a prop until its
//     destroy pass and then erases or deletes it;
//   - `CreateInterface` (Entity 0x0067A220, Unit 0x006AC2C0, ReconBlip 0x005BEE90) the first
//     time a view publishes the entity, `DestroyInterface` (0x0067A260) when it stops: whether
//     the view's client has the entity is per-view history the sim keeps in one bit;
//   - `SyncInterface`: the entity block as `Entity::SyncInterface` (0x0067A290) copies it, with
//     the attach parent and children rewritten from the live attach info, the view's
//     visibility mode and flag, and `mRequestRefreshUI` as the walk found it; a unit adds its
//     unit block with recon flags 0x1C (`Unit::SyncInterface` 0x006AC3A0); a blip adds its unit
//     block and overrides both from the view's recon record (`ReconBlip::SyncInterface`
//     0x005BEFB0), and keeps the vision range the view last copied from its creator.
//
// Plan WPR.35, `EnableTeams`: players on one team see nearly the same world (over 26978344's 16 players,
// about 80 % of what a view changes in a beat is changed the same in a teammate's), so most of it is
// worked out once. A team gets one more view, after the armies' views: plain entities, props and blips,
// the last from the record of the member who has it. An army's own view then holds only its real units.
// A player's client holds the two together, less the blips of its own units, which their army byte tells.
// Mutual allies share vision, so this shows a teammate nothing it couldn't see anyway; what can differ
// from a lockstep client is that a blip's update reaches all of a team when it reaches one of them.
// A team is fixed once made. An army that stops being a mutual ally of the rest is cut from it for good
// (`CutFromTeam`): its player keeps only their own view, as the team's would show them what their former
// allies see. Two teams that become allies keep their views apart, which hides from each what the other sees.
//
// The entity lanes are filled (creations, entity and unit updates, deletes and erases) and the
// army lane (plan WP5.4: every army's public record, the focus-only fields for the view's own
// army alone, `mIsAlly` for the view). The other lanes (Lua `Sync`, grids, commands, decals,
// effects) are other plan items.

namespace moho
{
  class Prop;
  struct SSTIArmyVariableData;
}

namespace faf::remote
{
  /**
   * Plan WP5.4: army `index`'s record as view `viewArmy` gets it (ViewPackets.cpp): every army's
   * public fields, the focus-only ones for the view's own army alone, and `mIsAlly` as the sim
   * would write it for that focus (`beforeFirstTick`: as the constructor leaves it).
   */
  [[nodiscard]] moho::SSTIArmyVariableData ArmyRecordForView(
    const moho::SSTIArmyVariableData& source, std::size_t index, std::int32_t viewArmy, bool beforeFirstTick
  );

  class CViewPackets : public CBeatChangeSet
  {
  public:
    CViewPackets();
    ~CViewPackets() override;

    /** The armies the last beat was built for (the sim's army count). */
    [[nodiscard]] std::int32_t ArmyCount() const noexcept { return mArmySlots; }
    /** The views the last beat was built for: one per army, then one per team with `EnableTeams`. */
    [[nodiscard]] std::size_t ViewSlots() const noexcept { return mPackets.size(); }

    /**
     * Plan WPR.35: from the first beat on, one view per team and an army's own view holding only its
     * real units (see above). Teams are every army with a view that is a mutual ally of all the rest.
     */
    void EnableTeams() noexcept { mWantTeams = true; }
    /**
     * Plan WP13.6, before the first beat, with `EnableTeams`: one more view after the teams', of everything as army -1
     * sees it (no blips), built only while a player watches it (`WatchEverything`). None without room for it.
     */
    void EnableObserverView() noexcept { mWantObserver = true; }
    /**
     * Plan WP13.6, on the sim thread: from the next beat that holds every entity, `army`'s player gets the observer
     * view as their team's and their own view empties (`OnWatchingEverything`), for good. False: there is no observer view.
     */
    bool WatchEverything(std::size_t army);
    [[nodiscard]] bool WatchesEverything(const std::size_t army) const noexcept { return army < 32u && ((mWatching >> army) & 1u) != 0u; }
    [[nodiscard]] bool TeamsOn() const noexcept { return mTeamsOn; }
    /** The team view of an army's view; the army's own without teams. */
    [[nodiscard]] std::size_t TeamSlotOf(const std::size_t army) const noexcept
    {
      return mTeamsOn && army < mTeamOfArmy.size() && mTeamOfArmy[army] >= 0 ? static_cast<std::size_t>(mArmySlots + mTeamOfArmy[army]) : army;
    }
    /** How many teams there are. */
    [[nodiscard]] std::size_t TeamCount() const noexcept { return mTeams.size(); }
    /** A team's view slot. */
    [[nodiscard]] std::size_t TeamSlot(const std::size_t team) const noexcept { return static_cast<std::size_t>(mArmySlots) + team; }
    /** The armies that share a team's id map, with or without views still, and whether or not cut from it since. */
    [[nodiscard]] const std::vector<std::int32_t>& TeamMembers(const std::size_t team) const noexcept { return mTeams[team].members; }
    /** The team's armies that are still in it, one bit each. */
    [[nodiscard]] std::uint32_t TeamMask(const std::size_t team) const noexcept { return mTeams[team].mask; }
    /**
     * Whether an army has left its team: no longer a mutual ally of the rest. It keeps its own view and the
     * team's id map, but gets nothing more of the team's view, and nothing of its own goes into it.
     */
    [[nodiscard]] bool CutFromTeam(const std::size_t army) const noexcept { return army < 32u && ((mCutArmies >> army) & 1u) != 0u; }

    /**
     * Builds the views on the sim's workers (plan WP5.7, under I3) from the next beat on. Off by
     * default; the views come out the same either way.
     */
    void SetParallel(bool parallel) noexcept { mParallel = parallel; }
    [[nodiscard]] bool Parallel() const noexcept { return mParallel; }
    /**
     * Builds no view for a civilian army (`IArmy::IsCivilian`) from the next beat on: no client
     * receives one (plan WPR.35). Off by default, so the checks still see every army. A skipped
     * view's packet and frame stay empty (`HasView`).
     */
    void SkipCivilianViews() noexcept { mSkipCivilians = true; }
    /** Builds views only for the armies of these bits from the next beat on: a game server's players. */
    void SetViewArmies(const std::uint32_t armies) noexcept { mViewArmies = armies; }
    /** Whether the last beat built `army`'s view. */
    [[nodiscard]] bool HasView(std::int32_t army) const { return mHasView[static_cast<std::size_t>(army)] != 0u; }
    /** Wall time spent building views since the start, in seconds (`AddBuildTime`). */
    [[nodiscard]] double BuildSeconds() const noexcept { return mBuildSeconds; }

    /** The steps of a beat's views on the sim thread, in order, timed with `EnablePhaseTimes`. */
    enum class EViewPhase : std::uint8_t
    {
      Read,    // the change set read once for every view
      ReadBlocks, // blips' vision and hash blocks handed out
      ReadBlips,  // blips' shared updates
      Build,   // each view's packet
      Write,   // what the views changed, written back
      Shared,  // records shared by several views
      Index,   // the entity index
      Facts,   // which views keep each entity
      Keep,    // whose answers changed
      Poses,   // the units' bones against what their clients hold, once for every view
      Tables,  // the session tables' edits and the units' stats, once for every view
      Frames,  // each view's frame
      Release, // stats trees let go of
      GridSetup, // the lanes' start: Lua routing, which grids go to whom
      Grids,   // intel grids encoded
      Lua,     // the Lua lane
      Count
    };
    /** One step's time over every beat: its wall time; for a step done one view at a time, the sum and the slowest view's. */
    struct SPhaseTime
    {
      double wall = 0.0;
      double viewSum = 0.0;
      double viewMax = 0.0;
      double teamViews = 0.0; // the team views' share of `viewSum`
    };
    /** Times each step of the views from the next beat on (headless's `--view-bench`). */
    void EnablePhaseTimes() noexcept { mPhaseTimesOn = true; }
    [[nodiscard]] bool PhaseTimesOn() const noexcept { return mPhaseTimesOn; }
    [[nodiscard]] const SPhaseTime& PhaseTime(const EViewPhase phase) const noexcept { return mPhaseTimes[static_cast<std::size_t>(phase)]; }

    /**
     * Plan WPR.35: from the next beat on, an entity update is not copied into the packet: `Direct`
     * lists what to read from the sim instead, valid until the sim runs on. Off by default, since
     * the checks compare the packets with what a lockstep client gets.
     */
    void SetDirectUpdates(const bool direct) noexcept { mDirectUpdates = direct; }
    /** With direct updates: plain entities and props share `records` (not owned). */
    void SetSharedRecords(CSharedEntityRecords* const records) noexcept { mSharedRecords = records; }
    /** The last beat's direct updates for `army`, in the change set's id order. */
    [[nodiscard]] const std::vector<SDirectUpdate>& Direct(const std::int32_t army) const { return mDirect[static_cast<std::size_t>(army)]; }

    /** The last beat's entity lanes for `army`, in the change set's id order. */
    [[nodiscard]] const moho::SSyncData& Packet(std::int32_t army) const { return *mPackets[static_cast<std::size_t>(army)]; }

  protected:
    void OnBeatChanges(moho::Sim& sim, const moho::SSyncData& packet) override;

    /** The views' packets of a sealed beat are ready (`Packet`). */
    virtual void OnViewPackets(moho::Sim& sim) { (void)sim; }
    /**
     * In `OnViewPackets`: the sim's own packet of the beat, as far as `Sim::Sync` has written it (the lanes before
     * its entity walk, such as the changed terrain rectangles; not its terrain field or deposits, written after).
     */
    [[nodiscard]] const moho::SSyncData* SyncPacket() const noexcept { return mSyncPacket; }

  private:
    static constexpr std::uint32_t kNoVisions = 0xFFFFFFFFu;
    static constexpr std::size_t kBlipViews = 32; // `kMaxViews`

    /** What the views' clients hold of one entity beyond its packed data; a bit per view. */
    struct SEntityViews
    {
      std::uint32_t created = 0;   // the views' `mInterfaceCreated`
      std::uint32_t hasVision = 0; // a blip: the views that copied its creator's vision range at least once
      std::uint32_t visions = kNoVisions; // that range per view: `mVisions[visions + army]`
      std::uint32_t blipHashes = kNoVisions; // the update each view's client holds: `mBlipHashes[blipHashes + army]`
    };

    /** One changed entity as every view reads it: read once a beat, written back after the views. */
    struct SChangedView
    {
      SDirectUpdate::STarget target;
      SEntityFacts facts;
      moho::Prop* prop = nullptr;
      std::uint32_t mayAct = 0;      // the views with something to do; the others skip the entity
      SEntityViews before;
      std::atomic<std::uint32_t> created{0};   // `before`'s as the views change them this beat
      std::atomic<std::uint32_t> hasVision{0};
      std::uint32_t creatorVision = 0; // with `hasCreator`: the range to copy
      bool hasCreator = false;
      // A blip whose update can be shared: its different updates this beat, from `firstBlipRecord`,
      // the army each is read for, and which one each view gets.
      std::uint8_t blipRecordCount = 0;
      std::uint8_t blipRecordView[kBlipViews]{};
      std::uint8_t blipRecordOf[kBlipViews]{};
      std::uint32_t firstBlipRecord = 0;
    };

    /** One team's view. */
    struct STeam
    {
      std::vector<std::int32_t> members;
      std::uint32_t mask = 0; // `members` not cut from it, one bit each
      bool observer = false;  // plan WP13.6: the view of everything (army -1); `members` are the players watching it
    };
    /** Plan WP13.6: the observer view's slot bit, while a player watches it. */
    [[nodiscard]] std::uint32_t ObserverBit() const noexcept
    {
      return mObserverTeam >= 0 && mWatching != 0u ? std::uint32_t{1} << (static_cast<std::size_t>(mArmySlots) + static_cast<std::size_t>(mObserverTeam)) : 0u;
    }

    /** The teams from who's allied with whom now. */
    void BuildTeams(const moho::Sim& sim);
    /** Cuts from its team every army no longer a mutual ally of the rest; warns once when two teams become allies. */
    void CheckTeams(const moho::Sim& sim);
    /** The first army still in a team: whose sight shows the team what isn't any member's own. */
    [[nodiscard]] std::int32_t TeamLead(const STeam& team) const noexcept;
    /** What a view does with an entity: the oracle's answer for an army's view, or as the section above says. */
    [[nodiscard]] SViewVisibility VisibilityFor(const moho::Sim& sim, std::int32_t view, const SEntityFacts& facts) const;
    /** The army whose recon record a view shows of a blip: its own, or the first of its team that has one. */
    [[nodiscard]] std::int32_t ReconArmyFor(std::int32_t view, const SEntityFacts& facts) const noexcept;

    /** Fills `mChanged` from the change set; the views only read the sim from here on. */
    void ReadChangedEntities(moho::Sim& sim);
    /** The range `army`'s view last copied from a blip's creator (`SyncForView`), read before the views run. */
    [[nodiscard]] bool ViewVision(const SChangedView& changed, std::size_t army, std::uint32_t& vision) const;
    /** Which of a blip's updates each view gets. */
    void MatchBlipViews(moho::Sim& sim, SChangedView& changed);
    /** What the views changed goes into `mEntityViews`. */
    void WriteChangedEntities();

    void SyncForView(moho::Sim& sim, std::int32_t army, SChangedView& changed, moho::SSyncData& out);

  protected:
    /** A new beat's views are about to be built. */
    virtual void OnBeatStarting() {}
    /** Plan WP13.6: `army`'s player watches the observer view from this beat on; their client needs it whole. */
    virtual void OnWatchingEverything(std::size_t army) { (void)army; }

    /** Adds the time from this beat's start to now to `BuildSeconds` (once the views are built). */
    void AddBuildTime() noexcept
    {
      mBuildSeconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - mBuildStart).count();
    }
    /** With phase times: the time since the last mark (or the beat's start) goes to `phase`, with the views' own times. */
    void MarkPhase(EViewPhase phase) noexcept;
    /** With phase times: runs `work` and records its time as view `slot`'s in the step under way. */
    template <class Work>
    void TimeView(const std::size_t slot, Work&& work)
    {
      if (!mPhaseTimesOn || slot >= mViewSeconds.size()) {
        work();
        return;
      }
      const auto start = std::chrono::steady_clock::now();
      work();
      mViewSeconds[slot] = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    }
    /** The facts of `Entities()[index]`, read this beat. */
    [[nodiscard]] const SEntityFacts& ChangedFacts(const std::size_t index) const noexcept { return mChanged[index].facts; }
    /** The views that keep an entity with these facts (`ViewsThatSee`, by slot), one bit each. */
    [[nodiscard]] std::uint32_t ViewsKeeping(const moho::Sim& sim, const SEntityFacts& facts) const;

  private:
    std::vector<std::unique_ptr<moho::SSyncData>> mPackets;
    std::int32_t mArmySlots = 0;
    bool mWantTeams = false;
    bool mTeamsOn = false;
    bool mTeamsJoined = false; // two teams became allies, which their views don't follow
    std::uint32_t mCutArmies = 0;
    std::vector<STeam> mTeams;
    std::vector<std::int32_t> mTeamOfArmy; // -1: none
    std::uint32_t mTeamBits = 0;           // the team views' slots, one bit each (not the observer view's)
    bool mWantObserver = false;            // plan WP13.6
    std::int32_t mObserverTeam = -1;       // the observer view's index in `mTeams`
    std::uint32_t mWatching = 0;           // the armies whose players watch it
    std::uint32_t mWatchPending = 0;       // and those who will, once a beat holds every entity
    std::vector<std::uint8_t> mHasView; // per army: its view is built (written on the sim thread)
    std::uint32_t mViewArmies = 0xFFFFFFFFu;
    std::vector<std::vector<SDirectUpdate>> mDirect;
    bool mDirectUpdates = false;
    CSharedEntityRecords* mSharedRecords = nullptr;
    bool mParallel = false;
    bool mSkipCivilians = false;
    std::chrono::steady_clock::time_point mBuildStart{};
    double mBuildSeconds = 0.0;
    bool mPhaseTimesOn = false;
    const moho::SSyncData* mSyncPacket = nullptr; // `SyncPacket`, during `OnBeatChanges`
    std::chrono::steady_clock::time_point mPhaseMark{};
    SPhaseTime mPhaseTimes[static_cast<std::size_t>(EViewPhase::Count)]{};
    std::vector<double> mViewSeconds; // this step's time per view slot (`TimeView`), each written by its own job
    std::unique_ptr<SChangedView[]> mChanged;
    std::vector<std::uint32_t> mBlipIndices; // this beat's changed blips with shared updates, by `mChanged` index
    std::size_t mChangedCapacity = 0;
    gpg::core::FlatGenerationMap<SEntityViews> mEntityViews; // entities a view has or had a vision range of
    gpg::core::ChunkedVector<std::uint32_t> mVisions; // a block of one per view for each blip with a creator
    std::vector<std::uint32_t> mFreeVisions;
    gpg::core::ChunkedVector<std::uint64_t> mBlipHashes; // a block of one per view for each blip with shared updates
    std::vector<std::uint32_t> mFreeBlipHashes;
  };
} // namespace faf::remote
