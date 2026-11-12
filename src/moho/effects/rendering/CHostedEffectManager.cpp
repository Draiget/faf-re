#include "moho/effects/rendering/CHostedEffectManager.h"

#include <new>

#include "moho/effects/rendering/CEfxBeam.h"
#include "moho/effects/rendering/CEfxEmitter.h"
#include "moho/effects/rendering/CEfxTrailEmitter.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"

// Engine addition (server mode, plan WP9.3): see CHostedEffectManager.h. Each create follows its
// `CEffectManagerImpl` namesake (CEffectManagerImpl.cpp, the addresses there) step for step; only the entity is a
// followed target, and the blueprint comes looked up.

namespace moho
{
  CHostedEffectManager::CHostedEffectManager(
    IEffectHost& host
  )
    : CEffectManagerImpl(nullptr)
    , mHost(host)
  {}

  CHostedEffectManager::~CHostedEffectManager()
  {
    // The base destructor deletes every effect through its own purge; nobody is told of those ends.
    mEnded = nullptr;
    while (!mActiveEffects.empty()) {
      TDatListItem<IEffect, void>* const node = mActiveEffects.pop_front();
      mDestroyedEffects.push_back(node);
    }
    PurgeDestroyedEffects();
  }

  const IEffectFollowTarget* CHostedEffectManager::Follows(
    const IEffect& effect,
    const bool beamEnd
  ) const noexcept
  {
    const auto found = mFollows.find(&effect);
    if (found == mFollows.end()) {
      return nullptr;
    }
    return beamEnd ? found->second.end.get() : found->second.start.get();
  }

  template <class TEffect>
  TEffect* CHostedEffectManager::Link(
    TEffect* const effect
  )
  {
    if (effect != nullptr) {
      effect->ListLinkBefore(&mActiveEffects);
    }
    return effect;
  }

  void CHostedEffectManager::ApplyFidelity(
    IEffect* const effect,
    const REffectBlueprint* const blueprint
  )
  {
    if (blueprint != nullptr && !EFFECT_EnabledAtFidelity(blueprint)) {
      DestroyEffect(effect);
    }
  }

  IEffect* CHostedEffectManager::HostEmitterAt(
    const Wm3::Vector3<float>& position,
    const REmitterBlueprint* const blueprint,
    const int army
  )
  {
    CEffectImpl* const effect = Link(new (std::nothrow) CEfxEmitter(this, position, army, blueprint));
    if (effect == nullptr) {
      return nullptr;
    }
    ApplyFidelity(effect, blueprint);
    return effect;
  }

  IEffect* CHostedEffectManager::HostAttachedEmitter(
    Target target,
    const int bone,
    const REmitterBlueprint* const blueprint,
    const int army
  )
  {
    CEffectImpl* const effect =
      Link(new (std::nothrow) CEfxEmitter(this, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f), army, blueprint));
    if (effect == nullptr) {
      return nullptr;
    }
    AttachBone(*effect, std::move(target), bone);
    ApplyFidelity(effect, blueprint);
    return effect;
  }

  IEffect* CHostedEffectManager::HostEmitterAtBone(
    const IEffectFollowTarget& target,
    const int bone,
    const REmitterBlueprint* const blueprint,
    const int army
  )
  {
    CEffectImpl* const effect =
      Link(new (std::nothrow) CEfxEmitter(this, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f), army, blueprint));
    if (effect == nullptr) {
      return nullptr;
    }
    // FUN_00659390: only the matrix, then `Interpolate` (CEffectManagerImpl.cpp, `ApplyBoneTransformToEffect`).
    const VTransform boneTransform = target.BoneWorld(bone);
    effect->mMatrix.Set(boneTransform.orient_, boneTransform.pos_);
    effect->Interpolate();
    ApplyFidelity(effect, blueprint);
    return effect;
  }

  IEffect* CHostedEffectManager::HostEmitterAtEntity(
    const IEffectFollowTarget& target,
    const REmitterBlueprint* const blueprint,
    const int army
  )
  {
    CEffectImpl* const effect =
      Link(new (std::nothrow) CEfxEmitter(this, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f), army, blueprint));
    if (effect == nullptr) {
      return nullptr;
    }
    // FUN_00659300: the position into slot 0, then `Interpolate` (`ApplyEntityWorldPositionToEffect`).
    effect->SetNParam(0, &target.Current().pos_.x, 3);
    effect->Interpolate();
    ApplyFidelity(effect, blueprint);
    return effect;
  }

  IEffect* CHostedEffectManager::HostEmitterOnEntity(
    Target target,
    const REmitterBlueprint* const blueprint,
    const int army
  )
  {
    CEffectImpl* const effect =
      Link(new (std::nothrow) CEfxEmitter(this, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f), army, blueprint));
    if (effect == nullptr) {
      return nullptr;
    }
    Attach(*effect, std::move(target));
    ApplyFidelity(effect, blueprint);
    return effect;
  }

  IEffect* CHostedEffectManager::HostTrail(
    Target target,
    const int bone,
    RTrailBlueprint* const blueprint,
    const int army
  )
  {
    if (blueprint == nullptr) {
      return nullptr; // the trail constructor reads it
    }
    const float initialPosition[3] = {0.0f, 0.0f, 0.0f};
    CEfxTrailEmitter* const effect = Link(new (std::nothrow) CEfxTrailEmitter(this, initialPosition, blueprint, army));
    if (effect == nullptr) {
      return nullptr;
    }
    AttachBone(*effect, std::move(target), bone);
    ApplyFidelity(effect, blueprint);
    return effect;
  }

  IEffect* CHostedEffectManager::HostBeam(
    const RBeamBlueprint* const blueprint,
    const int army
  )
  {
    if (blueprint == nullptr) {
      return nullptr; // the beam constructor reads it
    }
    CEfxBeam* const effect = Link(new (std::nothrow) CEfxBeam(this, blueprint, army));
    if (effect == nullptr) {
      return nullptr;
    }
    ApplyFidelity(effect, blueprint);
    return effect;
  }

  IEffect* CHostedEffectManager::HostBeamWithParams(
    const SCreateBeamParams& params,
    Target target,
    const int bone
  )
  {
    CEfxBeam* const effect = new (std::nothrow) CEfxBeam(this, params);
    if (effect == nullptr) {
      return nullptr;
    }
    // As 0x00656020: attached before it is linked, by entity for bone -1, else by bone.
    if (target != nullptr) {
      if (bone == -1) {
        Attach(*effect, std::move(target));
      } else {
        AttachBone(*effect, std::move(target), bone);
      }
    }
    return Link(effect);
  }

  IEffect* CHostedEffectManager::HostBeamBetween(
    const IEffectFollowTarget& source,
    const int sourceBone,
    const IEffectFollowTarget& target,
    const int targetBone,
    const RBeamBlueprint* const blueprint,
    const int army
  )
  {
    if (blueprint == nullptr) {
      return nullptr;
    }
    CEfxBeam* const effect = Link(new (std::nothrow) CEfxBeam(this, blueprint, army));
    if (effect == nullptr) {
      return nullptr;
    }
    const VTransform sourceTransform = source.BoneWorld(sourceBone);
    const float sourceLane[3] = {sourceTransform.pos_.x, sourceTransform.pos_.y, sourceTransform.pos_.z};
    const VTransform targetTransform = target.BoneWorld(targetBone);
    const float targetLane[3] = {targetTransform.pos_.x, targetTransform.pos_.y, targetTransform.pos_.z};
    effect->SetNParam(0, sourceLane, 3);
    effect->SetNParam(3, targetLane, 3);
    ApplyFidelity(effect, blueprint);
    return effect;
  }

  IEffect* CHostedEffectManager::HostAttachedBeamBetween(
    Target source,
    const int sourceBone,
    Target target,
    const int targetBone,
    const RBeamBlueprint* const blueprint,
    const int army
  )
  {
    if (blueprint == nullptr) {
      return nullptr;
    }
    CEfxBeam* const effect = Link(new (std::nothrow) CEfxBeam(this, blueprint, army));
    if (effect == nullptr) {
      return nullptr;
    }
    // `CEfxBeam::AttachEntityToEntity` (0x00655B50): the source by bone, then the end's target and its bone.
    AttachBone(*effect, std::move(source), sourceBone);
    effect->mEnd.mParentBoneIndex = targetBone < 0 ? 0 : targetBone;
    mFollows[effect].end = std::move(target);
    ApplyFidelity(effect, blueprint);
    return effect;
  }

  void CHostedEffectManager::Attach(
    IEffect& effect,
    Target target
  )
  {
    // `CEffectImpl::SetEntity` (0x006592D0) with a target: attached, the target's history starts again, interpolated.
    CEffectImpl& impl = static_cast<CEffectImpl&>(effect);
    impl.mNewAttachment = 1;
    if (target != nullptr && !EFFECT_LifetimeOnly()) {
      target->ResetHistory();
    }
    mFollows[&effect].start = std::move(target);
    impl.Interpolate();
  }

  void CHostedEffectManager::AttachBone(
    IEffect& effect,
    Target target,
    const int bone
  )
  {
    // `CEffectImpl::SetBone` (0x00659280) with a target.
    CEffectImpl& impl = static_cast<CEffectImpl&>(effect);
    impl.mNewAttachment = 1;
    impl.mEntityInfo.mParentBoneIndex = bone < 0 ? 0 : bone;
    if (target != nullptr && !EFFECT_LifetimeOnly()) {
      target->ResetHistory();
    }
    mFollows[&effect].start = std::move(target);
    impl.Interpolate();
  }

  void CHostedEffectManager::PurgeDestroyedEffects()
  {
    while (!mDestroyedEffects.empty()) {
      IEffect* const effect = mDestroyedEffects.ListGetNext();
      if (mEnded) {
        mEnded(*effect);
      }
      mFollows.erase(effect);
      delete effect;
    }
  }

  std::size_t CHostedEffectManager::ActiveCount() const noexcept
  {
    std::size_t count = 0;
    for (const IEffect* const effect : mActiveEffects.owners()) {
      (void)effect;
      ++count;
    }
    return count;
  }
} // namespace moho
