#pragma once

#include <cstdint>
#include <vector>

#include "moho/sim/Sim.h"

// Engine addition, server mode (plan WP5.1): the beat's change set, captured from the canonical
// sync walk. The server's sim runs unfocused, so its packet is the focus -1 packet: it carries
// no blips and no entity whose channel for "no focus" is Never. The views need those too, so
// they are built from the entities the walk synced, not from the packet's records. The walk is
// `Sim::Sync`'s: the dirty run (`Sim::mCoordEntities`: everything whose state changed this beat,
// blips whose recon record changed, units pinned there for life), or every entity on a focus
// change. An entity the walk did not sync kept its data; a view may still admit or drop it
// (visibility is the oracle's, every beat), but its packed data is the previous frame's.

namespace faf::remote
{
  /**
   * Collects the entities `Sim::Sync` syncs (`Sim::SetSyncObserver(this)`), and seals them as
   * one beat's change set when the walk is done. Reads only.
   */
  class CBeatChangeSet : public moho::CSyncObserver
  {
  public:
    void OnEntitySynced(moho::Entity& entity) override;
    void OnSyncWalkDone(moho::Sim& sim, const moho::SSyncData& packet) override;

    /**
     * The last sealed beat's synced entities, by id ascending. Raw pointers: valid until the sim
     * runs its next tick, so a reader takes what it needs from `OnBeatChanges`.
     */
    [[nodiscard]] const std::vector<moho::Entity*>& Entities() const noexcept { return mSealed; }
    /** The sealed beat (`Sim::mCurBeat` when its walk ended). */
    [[nodiscard]] std::uint32_t Beat() const noexcept { return mBeat; }

  protected:
    /** A beat was sealed: `Entities()` is its change set and `packet` its packet. */
    virtual void OnBeatChanges(moho::Sim& sim, const moho::SSyncData& packet)
    {
      (void)sim;
      (void)packet;
    }

  private:
    std::vector<moho::Entity*> mPending; // the walk in progress
    std::vector<moho::Entity*> mSealed;  // the last beat's, sorted by id
    std::uint32_t mBeat = 0;
  };
} // namespace faf::remote
