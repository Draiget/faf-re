#include "remote/BeatChangeSet.h"

#include <algorithm>

#include "moho/entity/Entity.h"

// Engine addition, server mode: see BeatChangeSet.h.

namespace faf::remote
{
  void CBeatChangeSet::OnEntitySynced(moho::Entity& entity)
  {
    mPending.push_back(&entity);
  }

  void CBeatChangeSet::OnSyncWalkDone(moho::Sim& sim, const moho::SSyncData& packet)
  {
    mSealed.swap(mPending);
    mPending.clear();
    // The dirty run is in link order; by id the change set merges with the views' id-ordered frames.
    std::sort(mSealed.begin(), mSealed.end(), [](const moho::Entity* const lhs, const moho::Entity* const rhs) {
      return static_cast<std::uint32_t>(lhs->id_) < static_cast<std::uint32_t>(rhs->id_);
    });
    mBeat = sim.mCurBeat;
    OnBeatChanges(sim, packet);
  }
} // namespace faf::remote
