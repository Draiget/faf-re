#include "remote/BeatChangeSet.h"

#include <algorithm>
#include <cstddef>
#include <utility>

#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"

// Engine addition, server mode: see BeatChangeSet.h.

namespace faf::remote
{
  void CBeatChangeSet::OnEntityWillSync(moho::Entity& entity)
  {
    mPendingRefreshUI = entity.mVarDat.mRequestRefreshUI != 0u;
  }

  void CBeatChangeSet::OnEntitySynced(moho::Entity& entity)
  {
    mPending.push_back(SChangedEntity{&entity, static_cast<std::uint32_t>(entity.id_), mPendingRefreshUI});
  }

  void CBeatChangeSet::OnSyncWalkDone(moho::Sim& sim, const moho::SSyncData& packet)
  {
    mSealed.swap(mPending);
    mPending.clear();
    // The dirty run is in link order; by id the change set merges with the views' id-ordered frames.
    std::sort(mSealed.begin(), mSealed.end(), [](const SChangedEntity& lhs, const SChangedEntity& rhs) { return lhs.id < rhs.id; });
    mEveryEntitySealed = std::exchange(mEveryEntity, false);
    if (mEveryEntitySealed && sim.mEntityDB != nullptr) {
      // Plan WP13.6: the rest of the sim's entities, each once, as a focus change's walk has them all.
      const std::size_t walked = mSealed.size();
      for (const auto& idAndEntity : sim.mEntityDB->mAllUnits) {
        moho::Entity* const entity = idAndEntity.second;
        if (entity == nullptr) {
          continue;
        }
        const auto id = static_cast<std::uint32_t>(entity->id_);
        const auto end = mSealed.begin() + static_cast<std::ptrdiff_t>(walked);
        const auto found = std::lower_bound(mSealed.begin(), end, id, [](const SChangedEntity& changed, const std::uint32_t value) { return changed.id < value; });
        if (found == end || found->id != id) {
          mSealed.push_back(SChangedEntity{entity, id, false});
        }
      }
      std::sort(mSealed.begin(), mSealed.end(), [](const SChangedEntity& lhs, const SChangedEntity& rhs) { return lhs.id < rhs.id; });
    }
    mBeat = sim.mCurBeat;
    OnBeatChanges(sim, packet);
  }
} // namespace faf::remote
