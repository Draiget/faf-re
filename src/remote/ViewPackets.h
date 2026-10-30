#pragma once

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

#include "remote/BeatChangeSet.h"

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

namespace faf::remote
{
  class CViewPackets : public CBeatChangeSet
  {
  public:
    CViewPackets();
    ~CViewPackets() override;

    /** The armies the last beat was built for (the sim's army count). */
    [[nodiscard]] std::int32_t ArmyCount() const noexcept { return static_cast<std::int32_t>(mPackets.size()); }

    /** The last beat's entity lanes for `army`, in the change set's id order. */
    [[nodiscard]] const moho::SSyncData& Packet(std::int32_t army) const { return *mPackets[static_cast<std::size_t>(army)]; }

  protected:
    void OnBeatChanges(moho::Sim& sim, const moho::SSyncData& packet) override;

    /** The views' packets of a sealed beat are ready (`Packet`). */
    virtual void OnViewPackets(moho::Sim& sim) { (void)sim; }

  private:
    /** What one view's client holds of one entity, beyond its packed data. */
    struct SViewEntity
    {
      bool created = false;     // the view's `mInterfaceCreated`
      bool hasVision = false;   // a blip: the view copied its creator's vision range at least once
      std::uint32_t vision = 0; // that range
    };

    void SyncForView(
      moho::Sim& sim, std::int32_t army, const SChangedEntity& changed, moho::SSyncData& out,
      std::unordered_map<std::uint32_t, SViewEntity>& view
    );

    std::vector<std::unique_ptr<moho::SSyncData>> mPackets;
    std::vector<std::unordered_map<std::uint32_t, SViewEntity>> mViews;
  };
} // namespace faf::remote
