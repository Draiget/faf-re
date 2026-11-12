#include "remote/client/EffectLaneApplier.h"

#include <algorithm>

// Engine addition, server mode: see EffectLaneApplier.h.

namespace faf::remote::client
{
  using moho::EEffectOp;

  const char* EffectSkipName(
    const EEffectSkip skip
  ) noexcept
  {
    switch (skip) {
    case EEffectSkip::EntityNotHeld:
      return "entity not held";
    case EEffectSkip::UnknownEffect:
      return "unknown effect";
    case EEffectSkip::UnknownName:
      return "name not sent";
    case EEffectSkip::UnknownBlueprint:
      return "blueprint not held";
    case EEffectSkip::Count:
      break;
    }
    return "?";
  }

  std::uint64_t SEffectApplyCounts::Skipped() const noexcept
  {
    std::uint64_t total = 0;
    for (const std::uint64_t count : skipped) {
      total += count;
    }
    return total;
  }

  void SEffectApplyCounts::Add(
    const SEffectApplyCounts& other
  ) noexcept
  {
    lanes += other.lanes;
    ops += other.ops;
    applied += other.applied;
    created += other.created;
    replaced += other.replaced;
    setters += other.setters;
    lights += other.lights;
    destroyedByScript += other.destroyedByScript;
    droppedWithEntity += other.droppedWithEntity;
    droppedWhole += other.droppedWhole;
    ended += other.ended;
    agedOut += other.agedOut;
    badLanes += other.badLanes;
    unticked += other.unticked;
    for (std::size_t i = 0; i < skipped.size(); ++i) {
      skipped[i] += other.skipped[i];
    }
  }

  namespace
  {
    /** Whether a create's effect follows `entity` (and a beam `entity2`): every create on an entity but those placed
     * there once. */
    [[nodiscard]] bool Follows(
      const EEffectOp op
    ) noexcept
    {
      return op != EEffectOp::CreateEmitter && op != EEffectOp::CreateEmitterAtBone &&
        op != EEffectOp::CreateEmitterAtEntity;
    }
  } // namespace

  void CEffectLaneApplier::Drop(
    const std::uint32_t id
  )
  {
    mTarget.Destroy(id);
    mLive.erase(id);
  }

  void CEffectLaneApplier::Create(
    const wire::SEffectLaneOp& op
  )
  {
    // The entities it needs: none for an emitter at a point or a beam from a blueprint (attached later), the attachment
    // for a beam from create parameters if it has one, both ends of a beam between two entities.
    bool needsEntity = true;
    bool needsSecond = false;
    switch (op.op) {
    case EEffectOp::CreateEmitter:
      needsEntity = false;
      break;
    case EEffectOp::CreateBeam:
      needsEntity = op.blueprint == 0u && op.entity >= 0;
      break;
    case EEffectOp::CreateBeamEntityToEntity:
    case EEffectOp::AttachBeamEntityToEntity:
      needsSecond = true;
      break;
    default:
      break;
    }
    // A create for an id held replaces it, whatever comes of the new one: the server sent the effect again.
    if (mLive.contains(op.id)) {
      Drop(op.id);
      ++mLast.replaced;
    }
    const bool placed = op.op == EEffectOp::CreateEmitterAtBone || op.op == EEffectOp::CreateEmitterAtEntity;
    if (
      (needsEntity && (op.entity < 0 || !mTarget.HoldsEntity(op.entity, placed))) ||
      (needsSecond && (op.entity2 < 0 || !mTarget.HoldsEntity(op.entity2, false)))
    ) {
      Skip(EEffectSkip::EntityNotHeld);
      return;
    }
    const std::string* const blueprint = mReader.Name(false, op.blueprint);
    const std::string* const texture = mReader.Name(true, op.texture);
    if ((op.blueprint != 0u && blueprint == nullptr) || (op.texture != 0u && texture == nullptr)) {
      Skip(EEffectSkip::UnknownName);
      return;
    }
    if (!mTarget.Create(op.id, op, blueprint, texture)) {
      Skip(EEffectSkip::UnknownBlueprint);
      return;
    }
    SLive live;
    live.lane = mLanes;
    if (Follows(op.op)) {
      live.entity = needsEntity ? op.entity : -1;
      live.entity2 = needsSecond ? op.entity2 : -1;
    }
    mLive[op.id] = live;
    ++mLast.created;
    ++mLast.applied;
  }

  void CEffectLaneApplier::ApplyOp(
    const wire::SEffectLaneOp& op
  )
  {
    ++mLast.ops;
    if (op.op == EEffectOp::CreateLightParticle) {
      const std::string* const texture = mReader.Name(true, op.texture);
      const std::string* const ramp = mReader.Name(true, op.texture2);
      if ((op.texture != 0u && texture == nullptr) || (op.texture2 != 0u && ramp == nullptr)) {
        Skip(EEffectSkip::UnknownName);
        return;
      }
      mTarget.Light(op, texture, ramp);
      ++mLast.lights;
      ++mLast.applied;
      return;
    }
    if (op.op < EEffectOp::CreateLightParticle) {
      Create(op);
      return;
    }
    const auto found = mLive.find(op.id);
    if (found == mLive.end()) {
      Skip(EEffectSkip::UnknownEffect);
      return;
    }
    found->second.lane = mLanes; // an op keeps it from `SetHorizon`'s forgetting
    switch (op.op) {
    case EEffectOp::DestroyByScript:
      Drop(op.id);
      ++mLast.destroyedByScript;
      ++mLast.applied;
      return;
    case EEffectOp::SetEntity:
    case EEffectOp::SetBone:
      // An attach to an entity the client lacks: the server takes it to drop the effect.
      if (op.entity < 0 || !mTarget.HoldsEntity(op.entity, false)) {
        Skip(EEffectSkip::EntityNotHeld);
        Drop(op.id);
        return;
      }
      found->second.entity = op.entity; // it follows its last attachment
      break;
    default:
      break;
    }
    mTarget.Change(op.id, op);
    ++mLast.setters;
    ++mLast.applied;
  }

  bool CEffectLaneApplier::Apply(
    const std::span<const std::uint8_t> lane,
    const bool whole
  )
  {
    mLast = SEffectApplyCounts{};
    ++mLanes;
    if (whole) {
      for (const auto& [id, live] : mLive) {
        mTarget.Destroy(id);
      }
      mLast.droppedWhole += mLive.size();
      mLive.clear();
    }
    if (mHorizon != 0u) {
      std::erase_if(mLive, [this](const auto& entry) {
        const bool old = mLanes - entry.second.lane > mHorizon;
        mLast.agedOut += old ? 1u : 0u;
        return old;
      });
    }
    if (wire::IsUntickedEffectLane(lane)) {
      ++mLast.unticked;
      mTarget.Unticked();
    }
    const bool ok = mReader.Read(lane, mOps);
    mLast.badLanes += ok ? 0u : 1u;
    mLast.lanes += mOps.empty() ? 0u : 1u;
    mMostOps = std::max<std::uint64_t>(mMostOps, mOps.size());
    for (const wire::SEffectLaneOp& op : mOps) {
      ApplyOp(op);
    }
    // Effects that follow an entity (or a beam end) the client no longer holds go with it.
    for (auto it = mLive.begin(); it != mLive.end();) {
      const SLive& live = it->second;
      const bool lost = (live.entity >= 0 && !mTarget.HoldsEntity(live.entity, false)) ||
        (live.entity2 >= 0 && !mTarget.HoldsEntity(live.entity2, false));
      if (lost) {
        mTarget.Destroy(it->first);
        ++mLast.droppedWithEntity;
        it = mLive.erase(it);
      } else {
        ++it;
      }
    }
    mTotal.Add(mLast);
    return ok;
  }

  void CEffectLaneApplier::Ended(
    const std::uint32_t id
  )
  {
    if (mLive.erase(id) != 0u) {
      ++mTotal.ended;
    }
  }
} // namespace faf::remote::client
