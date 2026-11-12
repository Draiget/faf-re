#include "remote/client/EffectHosting.h"

#include <algorithm>

#include "gpg/core/containers/String.h"
#include "moho/animation/CAniPose.h"
#include "moho/effects/rendering/CEfxBeam.h"
#include "moho/effects/rendering/CEfxEmitter.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/entity/Entity.h"
#include "moho/math/GridPos.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/SimDriver.h"
#include "remote/client/SyncRebuilder.h"

// Engine addition, server mode: see EffectHosting.h.

namespace faf::remote::client
{
  using moho::EEffectOp;

  namespace
  {
    [[nodiscard]] bool SameTransform(
      const moho::VTransform& a,
      const moho::VTransform& b
    ) noexcept
    {
      return a.pos_ == b.pos_ && a.orient_ == b.orient_;
    }

    /** The values an op carries, as a vector (`count` of them from `at`), or null when it has fewer. */
    [[nodiscard]] const float* Values(
      const wire::SEffectLaneOp& op,
      const std::size_t at,
      const std::size_t count
    ) noexcept
    {
      return op.values.size() >= at + count ? op.values.data() + at : nullptr;
    }
  } // namespace

  void CClientFollowTarget::Update(
    const SState& state
  )
  {
    // `Entity::AdvanceCoords` (0x00678F10): the previous position, then the new one, into the ring, when it moved.
    if (!SameTransform(state.current, mState.current) || !SameTransform(state.pending, mState.pending)) {
      mHistory[static_cast<std::size_t>(mCursor)] = mState.current;
      mCursor = (mCursor + 1) % kHistorySamples;
      mHistory[static_cast<std::size_t>(mCursor)] = state.current;
    }
    mState = state;
    mGone = false;
  }

  void CClientFollowTarget::MarkGone() noexcept
  {
    mGone = true;
    mState.pose.reset(); // the rebuilder's: not this target's to keep
  }

  const moho::VTransform& CClientFollowTarget::History(
    const int tick
  ) const
  {
    // `Entity::GetPositionHistory` (0x006794F0).
    const int delta = mCursor - tick;
    const int index = delta < 0 ? ((delta + 1) % kHistorySamples) + (kHistorySamples - 1) : delta % kHistorySamples;
    return mHistory[static_cast<std::size_t>(index)];
  }

  void CClientFollowTarget::ResetHistory() const
  {
    // `Entity::InitPositionHistory` (0x00678800): a fresh ring, every sample the default transform.
    mHistory.fill(moho::VTransform{});
    mCursor = 0;
  }

  moho::VTransform CClientFollowTarget::BoneLocal(
    const int bone
  ) const
  {
    if (mState.isUnit) {
      // `Unit::GetBoneLocalTransform` (0x006AA440): the pose's bone in the unit's space; root -1 at half its height.
      moho::VTransform local{};
      if (const moho::CAniPose* const pose = mState.pose.get(); pose != nullptr && bone >= 0) {
        const moho::CAniPoseBone* const begin = pose->mBones.begin();
        const moho::CAniPoseBone* const end = pose->mBones.end();
        if (
          begin != nullptr && end != nullptr && end >= begin &&
          static_cast<std::size_t>(bone) < std::size_t(end - begin)
        ) {
          return moho::VTransform::Compose(begin[bone].GetCompositeTransform(), pose->mLocalTransform.Inverse());
        }
      }
      if (bone == -1 && mState.blueprint != nullptr) {
        local.pos_.y = mState.blueprint->mSizeY * 0.5f;
      }
      return local;
    }
    // `Entity::GetBoneLocalTransform` (0x00679E20), shared with the sim.
    return moho::ENTITY_BoneLocalTransform(mState.mesh.get(), mState.scale, mState.blueprint, bone);
  }

  moho::VTransform CClientFollowTarget::BoneWorld(
    const int bone
  ) const
  {
    if (mState.isUnit) {
      // `Unit::GetBoneWorldTransform` (0x006AA5C0): the pose's bone; else the anchor on the pending transform.
      if (const moho::CAniPose* const pose = mState.pose.get(); pose != nullptr && bone >= 0) {
        const moho::CAniPoseBone* const begin = pose->mBones.begin();
        const moho::CAniPoseBone* const end = pose->mBones.end();
        if (
          begin != nullptr && end != nullptr && end >= begin &&
          static_cast<std::size_t>(bone) < std::size_t(end - begin)
        ) {
          return begin[bone].GetCompositeTransform();
        }
      }
      moho::VTransform anchor{};
      if (bone == -1 && mState.blueprint != nullptr) {
        anchor.pos_.y = mState.blueprint->mSizeY * 0.5f;
      }
      return moho::VTransform::Compose(mState.pending, anchor);
    }
    // `Entity::GetBoneWorldTransform` (0x00679CE0): the local bone (or the collision anchor) on the current transform.
    if (bone >= 0 || (bone == -1 && mState.blueprint != nullptr)) {
      return moho::VTransform::Compose(BoneLocal(bone), mState.current);
    }
    return mState.current;
  }

  bool CClientFollowTarget::UpdatesBeams() const
  {
    // A unit, a projectile or a collision beam. The client tells props apart by blueprint; anything else (a collision
    // beam, a script entity) keeps updating, which only costs a beam on a still entity its recomputation.
    if (mState.isUnit) {
      return true;
    }
    if (dynamic_cast<const moho::RProjectileBlueprint*>(mState.blueprint) != nullptr) {
      return true;
    }
    return dynamic_cast<const moho::RPropBlueprint*>(mState.blueprint) == nullptr;
  }

  CClientEffects::CClientEffects(
    moho::RRuleGameRules& rules,
    const CSyncRebuilder& rebuilder,
    std::function<bool(std::int32_t, bool)> holds,
    SEffectHostWorld world
  )
    : mRules(rules)
    , mRebuilder(rebuilder)
    , mHolds(std::move(holds))
    , mWorld(std::move(world))
    , mManager(std::make_unique<moho::CHostedEffectManager>(*this))
  {
    mManager->SetEndedHandler([this](const moho::IEffect& effect) {
      const auto found = mIds.find(&effect);
      if (found == mIds.end()) {
        return; // destroyed by an op: the applier already forgot it
      }
      const std::uint32_t id = found->second;
      mIds.erase(found);
      mEffects.erase(id);
      ++mCounts.endedByThemselves;
      if (mEnded) {
        mEnded(id);
      }
    });
  }

  CClientEffects::~CClientEffects()
  {
    mManager.reset(); // its effects go before the targets and maps they read
  }

  std::size_t CClientEffects::Alive() const noexcept
  {
    return mManager->ActiveCount();
  }

  moho::SParticleBuffer* CClientEffects::ParticleBuffer()
  {
    if (!mParticles) {
      mParticles.reset(new moho::SParticleBuffer());
    }
    return mParticles.get();
  }

  bool CClientEffects::FocusArmyDetects(
    const Wm3::Vec3f& position
  ) const
  {
    // The focus army's sight as the view's grid lane gives it: its grids and its allies', each a bit per cell. Under
    // water the water (sonar) grids. No grid of the kind: nothing hides (as `UserArmy::CanSeePoint` with none).
    if (mGrids == nullptr) {
      return true;
    }
    const std::uint8_t kind = WaterElevationAt(position.x, position.z) > position.y ? 1u : 0u;
    bool anyGrid = false;
    for (const wire::SGridSlot& slot : *mGrids) {
      if (slot.kind != kind || slot.gridSize == 0u) {
        continue;
      }
      anyGrid = true;
      Wm3::Vec3f cellPosition = position;
      const moho::GridPos cell(&cellPosition, static_cast<int>(slot.gridSize));
      if (
        cell.x >= 0 && cell.z >= 0 && static_cast<std::uint32_t>(cell.x) < slot.bits.width &&
        static_cast<std::uint32_t>(cell.z) < slot.bits.height
      ) {
        const std::size_t at = static_cast<std::size_t>(cell.z) * slot.bits.width + static_cast<std::size_t>(cell.x);
        if (at < slot.bits.cells.size() && slot.bits.cells[at] != 0u) {
          return true;
        }
      }
    }
    return !anyGrid;
  }

  float CClientEffects::WaterElevationAt(
    const float x,
    const float z
  ) const
  {
    return mMap != nullptr ? mMap->GetWaterElevationAt(x, z) : moho::kWaterBodyNoWater;
  }

  float CClientEffects::TerrainElevationAt(
    const float x,
    const float z
  ) const
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->GetHeightField() : nullptr;
    return field != nullptr ? field->GetElevation(x, z) : 0.0f;
  }

  bool CClientEffects::ReadState(
    const std::uint32_t id,
    const bool orRemoved,
    CClientFollowTarget::SState& out
  ) const
  {
    CSyncRebuilder::SHeldView view;
    if (!mRebuilder.FindHeld(id, orRemoved, view) || view.data == nullptr) {
      return false;
    }
    const moho::SSTIEntityVariableData& data = *view.data;
    // In the sim's effect tick an entity is still where the last beat left it (`mCurTransform`, before the tick's
    // `AdvanceCoords`) and moves to where this beat shows it. One the last frame removed stays where it was last shown.
    out.current = view.removed ? data.mCurTransform : data.mLastTransform;
    out.pending = data.mCurTransform;
    out.velocityScale = data.mCurImpactValue > 0.0f ? data.mCurImpactValue : 1.0f;
    out.mesh = data.mScmResource;
    out.scale = data.mScale;
    out.blueprint = view.blueprint;
    out.pose = view.removed ? boost::shared_ptr<moho::CAniPose>() : view.pose;
    out.isUnit = view.isUnit;
    return true;
  }

  CClientEffects::TargetPtr CClientEffects::Target(
    const std::int32_t entity,
    const bool orRemoved
  )
  {
    if (entity < 0) {
      return nullptr;
    }
    const auto id = static_cast<std::uint32_t>(entity);
    if (const auto found = mTargets.find(id); found != mTargets.end()) {
      return found->second;
    }
    CClientFollowTarget::SState state;
    CSyncRebuilder::SHeldView view;
    const bool live = mRebuilder.FindHeld(id, false, view) && view.data != nullptr;
    if (!ReadState(id, orRemoved, state)) {
      return nullptr;
    }
    auto target = std::make_shared<CClientFollowTarget>();
    target->Update(state);
    if (live) {
      mTargets.emplace(id, target); // refreshed every beat while held
      mCounts.mostTargets = std::max<std::uint64_t>(mCounts.mostTargets, mTargets.size());
    } else {
      target->MarkGone(); // the last frame removed it: only a placed create reads it, once
    }
    return target;
  }

  moho::IEffect* CClientEffects::Find(
    const std::uint32_t id
  ) const
  {
    const auto found = mEffects.find(id);
    return found != mEffects.end() ? found->second : nullptr;
  }

  void CClientEffects::BeginBeat(
    const std::uint32_t beat,
    const int focusArmy,
    const std::vector<wire::SGridSlot>& grids
  )
  {
    ++mCounts.beats;
    mBeat = beat;
    mFocusArmy = focusArmy;
    mGrids = &grids;
    mCameras.clear();
    if (mWorld.cameras) {
      mWorld.cameras(mCameras);
    }
    mMap = mWorld.map ? mWorld.map() : nullptr;
    for (auto it = mTargets.begin(); it != mTargets.end();) {
      CClientFollowTarget::SState state;
      if (ReadState(it->first, false, state)) {
        it->second->Update(state);
        ++it;
      } else {
        it->second->MarkGone(); // the effects that follow it end in this beat's tick
        it = mTargets.erase(it);
      }
    }
  }

  void CClientEffects::EndBeat(
    moho::SSyncData* const packet
  )
  {
    mManager->Tick();
    mManager->PurgeDestroyedEffects();
    mCounts.mostAlive = std::max<std::uint64_t>(mCounts.mostAlive, mEffects.size());
    if (!mParticles) {
      return;
    }
    mCounts.particles += mParticles->mParticles.size();
    mCounts.trails += mParticles->mTrails.size();
    mCounts.beams += mParticles->mBeams.size();
    mCounts.beatsDrawing += 1u;
    mCounts.mostParticles = std::max<std::uint64_t>(mCounts.mostParticles, mParticles->mParticles.size());
    if (packet != nullptr) {
      // As `Sim::Sync` hands the sim's over (0x00747693): the packet takes it, the next beat starts a fresh one.
      packet->mParticleBuffer = mParticles;
    }
    mParticles.reset();
  }

  bool CClientEffects::HoldsEntity(
    const std::int32_t entity,
    const bool orRemoved
  ) const
  {
    return mHolds(entity, orRemoved);
  }

  bool CClientEffects::Create(
    const std::uint32_t id,
    const wire::SEffectLaneOp& op,
    const std::string* const blueprint,
    const std::string* const texture
  )
  {
    // The applier already dropped a held id (a create replaces it).
    const auto emitter = [&](const moho::REmitterBlueprint*& out) {
      out = blueprint != nullptr ? moho::RULE_FindEmitterBlueprintByName(&mRules, blueprint->c_str()) : nullptr;
      return blueprint == nullptr || out != nullptr;
    };
    const auto beam = [&]() -> const moho::RBeamBlueprint* {
      if (blueprint == nullptr) {
        return nullptr;
      }
      // As the beam bindings look a beam up (EffectBlueprint.cpp).
      moho::RResId resId{};
      gpg::STR_InitFilename(&resId.name, blueprint->c_str());
      return mRules.GetBeamBlueprint(resId);
    };

    moho::IEffect* effect = nullptr;
    bool known = true; // a blueprint the client has, and every entity it names
    switch (op.op) {
    case EEffectOp::CreateEmitter: {
      const moho::REmitterBlueprint* bp = nullptr;
      const float* const at = Values(op, 0, 3);
      known = emitter(bp) && at != nullptr;
      if (known) {
        effect = mManager->HostEmitterAt(Wm3::Vector3<float>(at[0], at[1], at[2]), bp, op.army);
      }
      break;
    }
    case EEffectOp::CreateAttachedEmitter:
    case EEffectOp::CreateEmitterOnEntity: {
      const moho::REmitterBlueprint* bp = nullptr;
      TargetPtr target = Target(op.entity, false);
      known = emitter(bp) && target != nullptr;
      if (known) {
        effect = op.op == EEffectOp::CreateAttachedEmitter
          ? mManager->HostAttachedEmitter(std::move(target), op.bone, bp, op.army)
          : mManager->HostEmitterOnEntity(std::move(target), bp, op.army);
      }
      break;
    }
    case EEffectOp::CreateEmitterAtBone:
    case EEffectOp::CreateEmitterAtEntity: {
      const moho::REmitterBlueprint* bp = nullptr;
      const TargetPtr target = Target(op.entity, true); // an impact names the projectile the view just removed
      known = emitter(bp) && target != nullptr;
      if (known) {
        effect = op.op == EEffectOp::CreateEmitterAtBone ? mManager->HostEmitterAtBone(*target, op.bone, bp, op.army)
                                                         : mManager->HostEmitterAtEntity(*target, bp, op.army);
      }
      break;
    }
    case EEffectOp::CreateTrail: {
      moho::RTrailBlueprint* const bp =
        blueprint != nullptr ? moho::RULE_FindTrailBlueprintByName(&mRules, blueprint->c_str()) : nullptr;
      TargetPtr target = Target(op.entity, false);
      known = bp != nullptr && target != nullptr;
      if (known) {
        effect = mManager->HostTrail(std::move(target), op.bone, bp, op.army);
      }
      break;
    }
    case EEffectOp::CreateBeam: {
      if (op.blueprint != 0u) {
        const moho::RBeamBlueprint* const bp = beam();
        known = bp != nullptr;
        if (known) {
          effect = mManager->HostBeam(bp, op.army);
        }
        break;
      }
      // From create parameters (wire/EffectLane.h): start, end, lifetime, width, texture scale; the texture; the blend
      // mode in `param`. The colour and UV lanes don't travel: the parameters' defaults.
      const float* const v = Values(op, 0, 9);
      TargetPtr target = op.entity >= 0 ? Target(op.entity, false) : nullptr;
      known = v != nullptr && (op.entity < 0 || target != nullptr);
      if (known) {
        moho::SCreateBeamParams params;
        params.mAttachBoneIndex = op.bone;
        params.mAttachArmyIndex = op.army;
        params.mStart = Wm3::Vector3<float>(v[0], v[1], v[2]);
        params.mEnd = Wm3::Vector3<float>(v[3], v[4], v[5]);
        params.mLifetime = v[6];
        params.mWidth = v[7];
        params.mTextureScale = v[8];
        if (texture != nullptr) {
          params.mTexture.assign_owned(texture->c_str());
        }
        params.mBlendMode = op.param;
        effect = mManager->HostBeamWithParams(params, std::move(target), op.bone);
      }
      break;
    }
    case EEffectOp::CreateBeamEntityToEntity:
    case EEffectOp::AttachBeamEntityToEntity: {
      const moho::RBeamBlueprint* const bp = beam();
      const bool attach = op.op == EEffectOp::AttachBeamEntityToEntity;
      TargetPtr source = Target(op.entity, false);
      TargetPtr end = Target(op.entity2, false);
      known = bp != nullptr && source != nullptr && end != nullptr;
      if (known) {
        effect = attach
          ? mManager->HostAttachedBeamBetween(std::move(source), op.bone, std::move(end), op.bone2, bp, op.army)
          : mManager->HostBeamBetween(*source, op.bone, *end, op.bone2, bp, op.army);
      }
      break;
    }
    default:
      known = false;
      break;
    }
    if (effect == nullptr) {
      ++mCounts.createFailed;
      return false; // the applier counts it (a blueprint, or an entity, the client doesn't have)
    }
    (void)known;
    mEffects[id] = effect;
    mIds[effect] = id;
    ++mCounts.created;
    return true;
  }

  void CClientEffects::Change(
    const std::uint32_t id,
    const wire::SEffectLaneOp& op
  )
  {
    moho::IEffect* const effect = Find(id);
    if (effect == nullptr) {
      return;
    }
    auto& impl = static_cast<moho::CEffectImpl&>(*effect);
    // The server's indices are the effect's own table's (the same blueprints on both sides); one past it is refused
    // rather than written past the parameters.
    const auto fits = [&impl, &op](const std::size_t count) {
      return op.param >= 0 && static_cast<std::size_t>(op.param) + count <= impl.mParams.size() &&
        op.values.size() >= count;
    };
    switch (op.op) {
    case EEffectOp::SetFloat:
      if (fits(1u)) {
        effect->SetFloatParam(op.param, op.values[0]);
      }
      return;
    case EEffectOp::SetVector:
      if (fits(3u)) {
        const Wm3::Vector3f value(op.values[0], op.values[1], op.values[2]);
        effect->SetVectorParam(op.param, &value);
      }
      return;
    case EEffectOp::SetN:
      if (!op.values.empty() && fits(op.values.size())) {
        effect->SetNParam(op.param, op.values.data(), static_cast<std::int32_t>(op.values.size()));
      }
      return;
    case EEffectOp::SetCurve: {
      // Its bounds, then x y z per key (server/EffectOpRecorder.cpp). Only an emitter keeps curves.
      auto* const emitterEffect = dynamic_cast<moho::CEfxEmitter*>(effect);
      if (
        emitterEffect == nullptr || op.param < 0 || static_cast<std::size_t>(op.param) >= moho::kEmitterCurveCount ||
        op.values.size() < 4u || (op.values.size() - 4u) % 3u != 0u
      ) {
        return;
      }
      moho::SEfxCurve curve;
      curve.mBoundsMin = Wm3::Vector2f(op.values[0], op.values[1]);
      curve.mBoundsMax = Wm3::Vector2f(op.values[2], op.values[3]);
      for (std::size_t at = 4u; at + 2u < op.values.size(); at += 3u) {
        curve.mKeys.push_back(Wm3::Vector3f(op.values[at], op.values[at + 1u], op.values[at + 2u]));
      }
      effect->SetCurveParam(op.param, &curve);
      return;
    }
    case EEffectOp::SetEntity:
    case EEffectOp::SetBone: {
      TargetPtr target = Target(op.entity, false);
      if (target == nullptr) {
        return; // the applier drops an effect whose attach names an entity the client lacks
      }
      if (op.op == EEffectOp::SetEntity) {
        mManager->Attach(*effect, std::move(target));
      } else {
        mManager->AttachBone(*effect, std::move(target), op.bone);
      }
      return;
    }
    default:
      return;
    }
  }

  void CClientEffects::Destroy(
    const std::uint32_t id
  )
  {
    const auto found = mEffects.find(id);
    if (found == mEffects.end()) {
      return;
    }
    moho::IEffect* const effect = found->second;
    mIds.erase(effect);
    mEffects.erase(found);
    mManager->DestroyEffect(effect); // deleted at the purge, after this beat's tick
  }

  void CClientEffects::Light(
    const wire::SEffectLaneOp& op,
    const std::string* const texture,
    const std::string* const ramp
  )
  {
    const float* const v = Values(op, 0, 5); // position, size, lifetime
    if (v == nullptr) {
      return;
    }
    fa::string primary;
    fa::string secondary;
    if (texture != nullptr) {
      primary.assign_owned(texture->c_str());
    }
    if (ramp != nullptr) {
      secondary.assign_owned(ramp->c_str());
    }
    mManager->CreateLightParticle(Wm3::Vector3<float>(v[0], v[1], v[2]), primary, secondary, v[3], v[4], op.army);
    ++mCounts.lights;
  }
} // namespace faf::remote::client
