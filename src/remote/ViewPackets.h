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
    [[nodiscard]] std::int32_t ArmyCount() const noexcept { return static_cast<std::int32_t>(mPackets.size()); }

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
    /** Whether the last beat built `army`'s view. */
    [[nodiscard]] bool HasView(std::int32_t army) const { return mHasView[static_cast<std::size_t>(army)] != 0u; }
    /** Wall time spent building views since the start, in seconds (`AddBuildTime`). */
    [[nodiscard]] double BuildSeconds() const noexcept { return mBuildSeconds; }

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

  private:
    static constexpr std::uint32_t kNoVisions = 0xFFFFFFFFu;
    static constexpr std::size_t kBlipViews = 32; // `kMaxViews`

    /** What the views' clients hold of one entity beyond its packed data; a bit per view. */
    struct SEntityViews
    {
      std::uint32_t created = 0;   // the views' `mInterfaceCreated`
      std::uint32_t hasVision = 0; // a blip: the views that copied its creator's vision range at least once
      std::uint32_t visions = kNoVisions; // that range per view: `mVisions[visions + army]`
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
      std::uint8_t blipRecordArmy[kBlipViews]{};
      std::uint8_t blipRecordOf[kBlipViews]{};
      std::uint32_t firstBlipRecord = 0;
    };

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
    /** Adds the time from this beat's start to now to `BuildSeconds` (once the views are built). */
    void AddBuildTime() noexcept
    {
      mBuildSeconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - mBuildStart).count();
    }

  private:
    std::vector<std::unique_ptr<moho::SSyncData>> mPackets;
    std::vector<std::uint8_t> mHasView; // per army: its view is built (written on the sim thread)
    std::vector<std::vector<SDirectUpdate>> mDirect;
    bool mDirectUpdates = false;
    CSharedEntityRecords* mSharedRecords = nullptr;
    bool mParallel = false;
    bool mSkipCivilians = false;
    std::chrono::steady_clock::time_point mBuildStart{};
    double mBuildSeconds = 0.0;
    std::unique_ptr<SChangedView[]> mChanged;
    std::size_t mChangedCapacity = 0;
    gpg::core::FlatGenerationMap<SEntityViews> mEntityViews; // entities a view has or had a vision range of
    gpg::core::ChunkedVector<std::uint32_t> mVisions; // a block of one per view for each blip with a creator
    std::vector<std::uint32_t> mFreeVisions;
  };
} // namespace faf::remote
