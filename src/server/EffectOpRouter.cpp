#include "server/EffectOpRouter.h"

#include <algorithm>
#include <bit>

namespace faf::server
{
  using moho::EEffectOp;

  namespace
  {
    [[nodiscard]] bool IsCreate(
      const EEffectOp op
    ) noexcept
    {
      return op < EEffectOp::CreateLightParticle;
    }

    [[nodiscard]] bool IsAttach(
      const EEffectOp op
    ) noexcept
    {
      return op == EEffectOp::SetEntity || op == EEffectOp::SetBone;
    }
  } // namespace

  void CEffectRoutes::Keep(
    SLive& live,
    const SEffectBeat& beat,
    const SEffectBeatOp& op
  )
  {
    // The last op per (op, parameter): an earlier one leaves, its bytes cut out.
    if (!IsCreate(op.op)) {
      const auto old = std::find_if(live.parts.begin() + 1, live.parts.end(), [&op](const SPart& part) {
        return part.op == op.op && part.param == op.param;
      });
      if (old != live.parts.end()) {
        const SPart gone = *old;
        live.bytes.erase(
          live.bytes.begin() + static_cast<std::ptrdiff_t>(gone.offset),
          live.bytes.begin() + static_cast<std::ptrdiff_t>(gone.offset + gone.size)
        );
        mKeptBytes -= gone.size;
        const auto next = live.parts.erase(old);
        for (auto it = next; it != live.parts.end(); ++it) {
          it->offset -= gone.size;
        }
      }
    }
    live.parts.push_back(SPart{static_cast<std::uint32_t>(live.bytes.size()), op.size, op.op, op.param});
    live.bytes.insert(
      live.bytes.end(),
      beat.ops.begin() + static_cast<std::ptrdiff_t>(op.offset),
      beat.ops.begin() + static_cast<std::ptrdiff_t>(op.offset + op.size)
    );
    mKeptBytes += op.size;
  }

  void CEffectRoutes::TakeBeat(
    SEffectBeat& beat,
    const std::uint32_t views,
    const std::uint32_t watching,
    const SeePoint& seePoint,
    const ShownBy& shownBy
  )
  {
    // Last beat's ended effects leave; those that never reached a view were dropped for it.
    for (const std::uint32_t id : mEnding) {
      const auto found = mLive.find(id);
      if (found == mLive.end()) {
        continue; // ended twice (`DestroyByScript`, then the engine's `Destroy`)
      }
      const SLive& live = found->second;
      mDropped += static_cast<std::uint64_t>(std::popcount(views & ~live.everSent.load(std::memory_order_relaxed)));
      if (live.kept) {
        --mKept;
        mKeptBytes -= live.bytes.size();
      }
      mLive.erase(found);
    }
    mEnding.clear();

    for (SEffectBeatOp& op : beat.list) {
      if (op.op == EEffectOp::CreateLightParticle) {
        // At its beat only. From `CreateLightParticleIntel`: where each army's intel saw it; else where it's seen.
        const std::uint32_t armies = op.armies;
        op.views = ((armies != ~0u ? armies & views : seePoint(op.position)) | watching) & views;
        continue;
      }
      if (IsCreate(op.op)) {
        SLive& live = mLive.try_emplace(op.id).first->second;
        live.entity = op.entity;
        live.entity2 = op.entity2;
        live.positioned = op.op == EEffectOp::CreateEmitter;
        live.placed = op.op == EEffectOp::CreateEmitterAtBone || op.op == EEffectOp::CreateEmitterAtEntity;
        live.position = op.position;
        live.nameCount = op.nameCount;
        live.names = op.names;
        if (live.positioned) {
          mPositioned.push_back(op.id);
        }
        if (mKept < kMaxKept) {
          live.kept = true;
          ++mKept;
          Keep(live, beat, op);
        } else {
          ++mNotKept;
        }
        continue;
      }
      SLive* const live = Find(op.id);
      if (live == nullptr) {
        continue;
      }
      if (op.op == EEffectOp::DestroyByScript) {
        live->ended = true;
        mEnding.push_back(op.id);
        continue;
      }
      if (IsAttach(op.op)) {
        live->entity = op.entity; // the effect follows its last attachment
        live->placed = false;
      }
      if (live->kept) {
        Keep(*live, beat, op);
      }
    }
    for (const std::uint32_t id : beat.ended) {
      if (SLive* const live = Find(id); live != nullptr && !live->ended) {
        live->ended = true;
        mEnding.push_back(id);
      }
    }

    // Positioned effects: each view that sees the point now may have them from now on.
    std::size_t keep = 0;
    for (const std::uint32_t id : mPositioned) {
      SLive* const live = Find(id);
      if (live == nullptr || live->ended) {
        continue;
      }
      if ((live->seen & views) != views) {
        live->seen |= (seePoint(live->position) | watching) & views;
      }
      if ((live->seen & views) != views) {
        mPositioned[keep++] = id; // asked again next beat
      }
    }
    mPositioned.resize(keep);

    // Effects on entities: the views that draw the entity through a blip this beat (another army's unit), once per
    // entity.
    if (shownBy) {
      mShownCache.clear();
      const auto shown = [this, &shownBy, views](const std::int32_t entity) -> std::uint32_t {
        if (entity < 0) {
          return 0u;
        }
        const auto [it, inserted] = mShownCache.try_emplace(entity);
        if (inserted) {
          it->second.blips.fill(-1);
          it->second.views = shownBy(entity, it->second.blips) & views;
        }
        return it->second.views;
      };
      for (auto& [id, live] : mLive) {
        if (live.ended || live.positioned) {
          continue;
        }
        live.shown = shown(live.entity);
        live.shown2 = shown(live.entity2);
      }
    }
  }

  std::int32_t CEffectRoutes::BlipShownTo(
    const std::int32_t entity,
    const std::size_t view
  ) const noexcept
  {
    const auto found = mShownCache.find(entity);
    if (found == mShownCache.end() || view >= found->second.blips.size()) {
      return -1;
    }
    return ((found->second.views >> view) & 1u) != 0u ? found->second.blips[view] : -1;
  }

  std::size_t CEffectRoutes::HeldBy(
    const std::size_t view
  ) const noexcept
  {
    const std::uint32_t bit = view < 32u ? std::uint32_t{1} << view : 0u;
    std::size_t held = 0;
    for (const auto& [id, live] : mLive) {
      held += !live.ended && (live.sent.load(std::memory_order_relaxed) & bit) != 0u ? 1u : 0u;
    }
    return held;
  }

  void CEffectViewRoute::Write(
    const SEffectBeat& beat,
    CEffectRoutes& routes,
    const std::size_t view,
    const bool fresh,
    const Holds& holds,
    std::vector<std::uint8_t>& lane,
    const ClientId& clientId
  )
  {
    const std::uint32_t bit = view < 32u ? std::uint32_t{1} << view : 0u;
    if (fresh) {
      // Its client holds nothing: every name and every effect it gets goes again.
      mNames.Reset();
      routes.ForEachLive([bit](CEffectRoutes::SLive& live) {
        live.sent.fetch_and(~bit, std::memory_order_relaxed);
      });
    }
    mNames.Begin();
    mOps.clear();
    std::uint32_t count = 0;
    // Plan WP9.3: an entity as this view's client holds it: a record of its frames (or one this beat's frame removed)
    // by the record's id, another army's unit by the id of the blip its client draws, otherwise none.
    const EffectEntityToClient toClient = [&](const std::int32_t entity) -> std::int32_t {
      std::int32_t client = -1;
      if (holds(entity, true) && clientId(entity, client)) {
        ++mTranslated;
        return client;
      }
      if (const std::int32_t blip = routes.BlipShownTo(entity, view); blip >= 0 && clientId(blip, client)) {
        ++mTranslated;
        return client;
      }
      ++mUntranslated;
      return -1;
    };
    const auto take = [this, &clientId, &toClient](
                        const std::uint8_t* const bytes,
                        const std::size_t size,
                        const SEffectBeatName* const names,
                        const std::size_t nameCount,
                        const bool namesEntities
                      ) {
      if (!clientId || !namesEntities || !AppendWithClientEntities({bytes, size}, toClient, mOps)) {
        mOps.insert(mOps.end(), bytes, bytes + size);
      }
      for (std::size_t i = 0; i < nameCount; ++i) {
        mNames.Need(names[i]);
      }
    };
    const auto namesEntities = [](const SEffectBeatOp& op) {
      return op.entity >= 0 || op.entity2 >= 0;
    };
    // Its client holds the entities (as records of its frames, or another army's unit as a blip it draws).
    const auto placeable =
      [&holds, bit](const CEffectRoutes::SLive& live, const std::int32_t entity, const std::int32_t entity2) {
      const bool first = entity >= 0 && ((live.shown & bit) != 0u || holds(entity, false));
      return first && (entity2 < 0 || (live.shown2 & bit) != 0u || holds(entity2, false));
    };

    // The beat's ops, in order.
    for (const SEffectBeatOp& op : beat.list) {
      const std::uint8_t* const bytes = beat.ops.data() + op.offset;
      if (op.op == EEffectOp::CreateLightParticle) {
        if ((op.views & bit) != 0u) {
          take(bytes, op.size, op.names.data(), op.nameCount, false);
          ++count;
          ++mLights;
        }
        continue;
      }
      CEffectRoutes::SLive* const live = routes.Find(op.id);
      if (live == nullptr || bit == 0u) {
        continue;
      }
      if (IsCreate(op.op)) {
        // A placed create (at an entity or a bone, not following it) also goes when its entity left the view this
        // beat: a projectile's impact is made as the projectile goes, and its client places it from the entity's last
        // state.
        const bool here = live->positioned ? (live->seen & bit) != 0u
          : live->placed                   ? op.entity >= 0 && ((live->shown & bit) != 0u || holds(op.entity, true))
                                           : placeable(*live, op.entity, op.entity2);
        if (here) {
          take(bytes, op.size, op.names.data(), op.nameCount, namesEntities(op));
          ++count;
          live->sent.fetch_or(bit, std::memory_order_relaxed);
          live->everSent.fetch_or(bit, std::memory_order_relaxed);
        } else {
          ++mHeld;
        }
      } else if ((live->sent.load(std::memory_order_relaxed) & bit) != 0u) {
        // Its client holds the effect. An attach or the script's destroy goes as it is (one to an entity the client
        // lacks makes it drop the effect); another setter only while the effect stays where the client can place it,
        // since one whose entity left this beat is dropped below.
        if (
          IsAttach(op.op) || op.op == EEffectOp::DestroyByScript || live->positioned || live->placed || !live->kept ||
          placeable(*live, live->entity, live->entity2)
        ) {
          take(bytes, op.size, nullptr, 0u, namesEntities(op));
          ++count;
        }
      }
    }

    // Live effects whose place this view's client holds now and lacks the effect get it whole; those whose entity it
    // lost, it dropped.
    if (bit != 0u) {
      routes.ForEachLive([&](CEffectRoutes::SLive& live) {
        if (live.ended) {
          return;
        }
        const bool held = (live.sent.load(std::memory_order_relaxed) & bit) != 0u;
        const bool here = live.positioned ? (live.seen & bit) != 0u : placeable(live, live.entity, live.entity2);
        if (here && !held && live.kept) {
          take(live.bytes.data(), live.bytes.size(), live.names.data(), live.nameCount, true);
          count += static_cast<std::uint32_t>(live.parts.size());
          live.sent.fetch_or(bit, std::memory_order_relaxed);
          live.everSent.fetch_or(bit, std::memory_order_relaxed);
          ++mReleased;
        } else if (!here && held && !live.positioned && !live.placed && live.kept) {
          live.sent.fetch_and(~bit, std::memory_order_relaxed);
          ++mWithdrawn;
        }
      });
    }

    mNames.Finish(mOps, count, lane);
    mOpsSent += count;
  }
} // namespace faf::server
