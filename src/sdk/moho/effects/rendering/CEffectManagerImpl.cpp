#include "moho/effects/rendering/CEffectManagerImpl.h"

#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/effects/rendering/CEfxBeam.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/entity/Entity.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/particles/BeamRenderHelpers.h"
#include "moho/particles/CParticleTextureCountedPtr.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/CParticleTexture.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/REffectBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/resource/RResId.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"

namespace moho
{
  gpg::RType* CEffectManagerImpl::sType = nullptr;

  gpg::RType* CEffectManagerImpl::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CEffectManagerImpl));
    }
    return sType;
  }

  namespace
  {
    [[nodiscard]] msvc8::string BuildParticleTexturePath(
      const msvc8::string& textureName,
      const char* const defaultPath
    )
    {
      if (textureName.empty()) {
        if (defaultPath == nullptr) {
          return msvc8::string{};
        }
        return msvc8::string(defaultPath);
      }
      return msvc8::string("/textures/particles/") + textureName + ".dds";
    }

    [[nodiscard]] bool IsBlueprintEnabledForCurrentFidelity(const REffectBlueprint* const blueprint)
    {
      if (blueprint == nullptr) {
        return true;
      }

      const int enabledMask = static_cast<int>(blueprint->LowFidelity)
        | (static_cast<int>(blueprint->MedFidelity) << 1)
        | (static_cast<int>(blueprint->HighFidelity) << 2);
      return (enabledMask & (1 << graphics_Fidelity)) != 0;
    }

    template <class TEffect>
    [[nodiscard]] TEffect* LinkActiveEffect(TDatList<IEffect, void>& activeEffects, TEffect* const effect)
    {
      if (effect == nullptr) {
        return nullptr;
      }

      effect->mManagerListNode.ListLinkBefore(&activeEffects);
      return effect;
    }

    [[nodiscard]] REmitterBlueprint* LookupEmitterBlueprint(Sim* const sim, const char* const blueprintName)
    {
      if (sim == nullptr || sim->mRules == nullptr || blueprintName == nullptr) {
        return nullptr;
      }

      RResId emitterId{};
      gpg::STR_InitFilename(&emitterId.name, blueprintName);
      return sim->mRules->GetEmitterBlueprint(emitterId);
    }

    [[nodiscard]] RTrailBlueprint* LookupTrailBlueprint(Sim* const sim, const char* const blueprintName)
    {
      if (sim == nullptr || sim->mRules == nullptr || blueprintName == nullptr) {
        return nullptr;
      }

      RResId trailId{};
      gpg::STR_InitFilename(&trailId.name, blueprintName);
      return sim->mRules->GetTrailBlueprint(trailId);
    }

    void SetEffectWorldPosition(IEffect& effect, const Wm3::Vector3f& position)
    {
      const float positionValues[3] = {position.x, position.y, position.z};
      effect.SetNParam(0, positionValues, 3);
    }

    void ApplyEmitterBlueprintParams(CEffectImpl& effect, const REmitterBlueprint* const blueprint)
    {
      effect.SetFloatParam(6, 1.0f);
      effect.SetFloatParam(3, 0.0f);
      effect.SetFloatParam(18, 1.0f);

      if (blueprint == nullptr) {
        effect.Interpolate();
        return;
      }

      effect.SetFloatParam(4, blueprint->Lifetime);
      effect.SetFloatParam(5, blueprint->RepeatTime);
      effect.SetFloatParam(8, blueprint->TextureFrameCount);
      effect.SetFloatParam(7, static_cast<float>(blueprint->BlendMode));
      effect.SetFloatParam(19, blueprint->LODCutoff);

      effect.SetFloatParam(9, blueprint->LocalVelocity ? 1.0f : 0.0f);
      effect.SetFloatParam(10, blueprint->LocalAcceleration ? 1.0f : 0.0f);
      effect.SetFloatParam(11, blueprint->Gravity ? 1.0f : 0.0f);
      effect.SetFloatParam(12, blueprint->AlignRotation ? 1.0f : 0.0f);
      effect.SetFloatParam(13, blueprint->InterpolateEmission ? 1.0f : 0.0f);
      effect.SetFloatParam(14, blueprint->TextureStripCount);
      effect.SetFloatParam(15, blueprint->AlignToBone ? 1.0f : 0.0f);
      effect.SetFloatParam(16, blueprint->SortOrder);
      effect.SetFloatParam(17, static_cast<float>(blueprint->Flat));
      effect.SetFloatParam(20, blueprint->EmitIfVisible ? 1.0f : 0.0f);
      effect.SetFloatParam(21, blueprint->CatchupEmit ? 1.0f : 0.0f);
      effect.SetFloatParam(22, blueprint->CreateIfVisible ? 1.0f : 0.0f);
      effect.SetFloatParam(23, blueprint->SnapToWaterline ? 1.0f : 0.0f);
      effect.SetFloatParam(24, blueprint->OnlyEmitOnWater ? 1.0f : 0.0f);
      effect.SetFloatParam(25, blueprint->ParticleResistance ? 1.0f : 0.0f);

      effect.OnInit(0, blueprint->TextureName.c_str());
      effect.OnInit(1, blueprint->RampTextureName.c_str());
      effect.Interpolate();
    }

    /**
     * Address: 0x00659390 (FUN_00659390)
     *
     * What it does:
     * Fetches one entity bone world transform, copies its position into the
     * effect payload, rebuilds the effect matrix from the same transform, and
     * advances interpolation once.
     */
    void ApplyBoneTransformToEffect(CEffectImpl& effect, Entity* const entity, const int boneIndex)
    {
      const VTransform boneTransform = entity->GetBoneWorldTransform(boneIndex);
      SetEffectWorldPosition(effect, boneTransform.pos_);
      effect.mMatrix.Set(boneTransform.orient_, boneTransform.pos_);
      effect.Interpolate();
    }

    /**
     * Address: 0x00659300 (FUN_00659300)
     *
     * What it does:
     * Copies one entity transform payload into stack lanes, writes the world
     * position lane into effect param slot `0` (`SetNParam(...,3)`), then
     * advances one interpolation step.
     */
    void ApplyEntityWorldPositionToEffect(CEffectImpl& effect, const Entity& entity)
    {
      struct EntityTransformStackLane
      {
        Vector4f orientation;   // +0x00
        Wm3::Vector3f position; // +0x10
      };
      static_assert(sizeof(EntityTransformStackLane) == 0x1C, "EntityTransformStackLane size must be 0x1C");
      static_assert(
        offsetof(EntityTransformStackLane, position) == 0x10,
        "EntityTransformStackLane::position offset must be 0x10"
      );

      const EntityTransformStackLane stackLane{entity.Orientation, entity.Position};
      effect.SetNParam(0, &stackLane.position.x, 3);
      effect.Interpolate();
    }

    void ApplyTrailBlueprintParams(CEffectImpl& effect, const RTrailBlueprint* const blueprint)
    {
      effect.SetFloatParam(5, 1.0f);

      if (blueprint != nullptr) {
        effect.SetFloatParam(3, blueprint->Lifetime);
        effect.SetFloatParam(4, blueprint->TrailLength);
        effect.OnInit(0, blueprint->RepeatTexture.c_str());
        effect.OnInit(1, blueprint->RampTexture.c_str());
      }

      effect.Interpolate();
    }

    /**
     * Address: 0x0066B430 (FUN_0066B430)
     *
     * What it does:
     * Unlinks one manager-list node from its current intrusive list and resets
     * that node back to self-linked sentinel form.
     */
    [[maybe_unused]] IEffect::ManagerListNode* UnlinkManagerListNodeAndSelfReference(
      IEffect::ManagerListNode* const node
    ) noexcept
    {
      if (node == nullptr) {
        return nullptr;
      }

      IEffect::ManagerListNode* const previous = node->mPrev;
      IEffect::ManagerListNode* const next = node->mNext;
      if (previous != nullptr) {
        previous->mNext = next;
      }
      if (next != nullptr) {
        next->mPrev = previous;
      }

      node->mPrev = node;
      node->mNext = node;
      return node;
    }
  } // namespace

  /**
   * Address: 0x0066B3E0 (FUN_0066B3E0, Moho::CEffectManagerImpl::CEffectManagerImpl)
   *
   * What it does:
   * Initializes one effect-manager implementation object by binding the
   * owning `Sim` lane and self-linking both intrusive effect lists.
   */
  CEffectManagerImpl::CEffectManagerImpl(Sim* const sim)
    : mSim(sim)
    , mActiveEffects()
    , mDestroyedEffects()
  {
  }

  /**
   * Address: 0x0066B400 (FUN_0066B400, Moho::CEffectManagerImpl::dtr thunk)
   * Address: 0x0066B450 (FUN_0066B450, Moho::CEffectManagerImpl::~CEffectManagerImpl body)
   */
  CEffectManagerImpl::~CEffectManagerImpl()
  {
    // Preserve dtor behavior: migrate still-active effects into the pending
    // destroy list, then purge that list.
    while (!mActiveEffects.empty()) {
      TDatListItem<IEffect, void>* const node = mActiveEffects.pop_front();
      mDestroyedEffects.push_back(node);
    }

    PurgeDestroyedEffects();
  }

  /**
   * Address: 0x0066B220 (FUN_0066B220, Moho::CEffectManagerImpl::GetSim)
   */
  Sim* CEffectManagerImpl::GetSim() const
  {
    return mSim;
  }

  /**
   * Address: 0x0065E220 (FUN_0065E220, Moho::CEffectManagerImpl::CreateEmitter)
   */
  IEffect* CEffectManagerImpl::CreateEmitter(
    const Wm3::Vector3<float> position,
    const char* const blueprintName,
    const int armyIndex
  )
  {
    (void)armyIndex;

    Sim* const sim = GetSim();
    REmitterBlueprint* const blueprint = LookupEmitterBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create emitter as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    CEffectImpl* const effect = LinkActiveEffect(mActiveEffects, new (std::nothrow) CEffectImpl());
    if (effect == nullptr) {
      return nullptr;
    }

    SetEffectWorldPosition(*effect, position);
    ApplyEmitterBlueprintParams(*effect, blueprint);

    if (blueprint != nullptr && !IsBlueprintEnabledForCurrentFidelity(blueprint)) {
      DestroyEffect(effect);
    }

    return effect;
  }

  /**
   * Address: 0x0065E390 (FUN_0065E390, Moho::CEffectManagerImpl::CreateAttachedEmitter)
   */
  IEffect* CEffectManagerImpl::CreateAttachedEmitter(
    Entity* const entity,
    const int boneIndex,
    const char* const blueprintName,
    const int armyIndex
  )
  {
    (void)armyIndex;

    Sim* const sim = GetSim();
    REmitterBlueprint* const blueprint = LookupEmitterBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create emitter as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    CEffectImpl* const effect = LinkActiveEffect(mActiveEffects, new (std::nothrow) CEffectImpl());
    if (effect == nullptr) {
      return nullptr;
    }

    SetEffectWorldPosition(*effect, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f));
    ApplyEmitterBlueprintParams(*effect, blueprint);
    effect->SetBone(entity, boneIndex);

    if (blueprint != nullptr && !IsBlueprintEnabledForCurrentFidelity(blueprint)) {
      DestroyEffect(effect);
    }

    return effect;
  }

  /**
   * Address: 0x0065E520 (FUN_0065E520, Moho::CEffectManagerImpl::CreateEmitterAtBone)
   */
  IEffect* CEffectManagerImpl::CreateEmitterAtBone(
    Entity* const entity,
    const int boneIndex,
    const char* const blueprintName,
    const int armyIndex
  )
  {
    (void)armyIndex;

    Sim* const sim = GetSim();
    REmitterBlueprint* const blueprint = LookupEmitterBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create emitter as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    CEffectImpl* const effect = LinkActiveEffect(mActiveEffects, new (std::nothrow) CEffectImpl());
    if (effect == nullptr) {
      return nullptr;
    }

    SetEffectWorldPosition(*effect, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f));
    ApplyEmitterBlueprintParams(*effect, blueprint);

    ApplyBoneTransformToEffect(*effect, entity, boneIndex);

    if (blueprint != nullptr && !IsBlueprintEnabledForCurrentFidelity(blueprint)) {
      DestroyEffect(effect);
    }

    return effect;
  }

  /**
   * Address: 0x0065E6B0 (FUN_0065E6B0, Moho::CEffectManagerImpl::CreateEmitterAtEntity)
   */
  IEffect* CEffectManagerImpl::CreateEmitterAtEntity(
    Entity* const entity,
    const char* const blueprintName,
    const int armyIndex
  )
  {
    (void)armyIndex;

    Sim* const sim = GetSim();
    REmitterBlueprint* const blueprint = LookupEmitterBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create emitter as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    CEffectImpl* const effect = LinkActiveEffect(mActiveEffects, new (std::nothrow) CEffectImpl());
    if (effect == nullptr) {
      return nullptr;
    }

    SetEffectWorldPosition(*effect, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f));
    ApplyEmitterBlueprintParams(*effect, blueprint);
    ApplyEntityWorldPositionToEffect(*effect, *entity);

    if (blueprint != nullptr && !IsBlueprintEnabledForCurrentFidelity(blueprint)) {
      DestroyEffect(effect);
    }

    return effect;
  }

  /**
   * Address: 0x0065E840 (FUN_0065E840, Moho::CEffectManagerImpl::CreateEmitterOnEntity)
   */
  IEffect* CEffectManagerImpl::CreateEmitterOnEntity(
    Entity* const entity,
    const char* const blueprintName,
    const int armyIndex
  )
  {
    (void)armyIndex;

    Sim* const sim = GetSim();
    REmitterBlueprint* const blueprint = LookupEmitterBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create emitter as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    CEffectImpl* const effect = LinkActiveEffect(mActiveEffects, new (std::nothrow) CEffectImpl());
    if (effect == nullptr) {
      return nullptr;
    }

    SetEffectWorldPosition(*effect, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f));
    ApplyEmitterBlueprintParams(*effect, blueprint);
    effect->SetEntity(entity);

    if (blueprint != nullptr && !IsBlueprintEnabledForCurrentFidelity(blueprint)) {
      DestroyEffect(effect);
    }

    return effect;
  }

  /**
   * Address: 0x006720F0 (FUN_006720F0, Moho::CEffectManagerImpl::CreateTrail)
   */
  IEffect* CEffectManagerImpl::CreateTrail(
    Entity* const entity,
    const int boneIndex,
    const char* const blueprintName,
    const int armyIndex
  )
  {
    (void)armyIndex;

    Sim* const sim = GetSim();
    RTrailBlueprint* const blueprint = LookupTrailBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create trail as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    CEffectImpl* const effect = LinkActiveEffect(mActiveEffects, new (std::nothrow) CEffectImpl());
    if (effect == nullptr) {
      return nullptr;
    }

    SetEffectWorldPosition(*effect, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f));
    ApplyTrailBlueprintParams(*effect, blueprint);
    effect->SetBone(entity, boneIndex);

    if (blueprint != nullptr && !IsBlueprintEnabledForCurrentFidelity(blueprint)) {
      DestroyEffect(effect);
    }

    return effect;
  }

  /**
   * Address: 0x0066B230 (FUN_0066B230, Moho::CEffectManagerImpl::DestroyEffect)
   */
  void CEffectManagerImpl::DestroyEffect(IEffect* const effect)
  {
    if (effect == nullptr) {
      return;
    }

    (void)UnlinkManagerListNodeAndSelfReference(&effect->mManagerListNode);
    effect->mManagerListNode.ListLinkBefore(&mDestroyedEffects);
  }

  /**
   * Address: 0x0066B4F0 (FUN_0066B4F0, Moho::CEffectManagerImpl::Tick)
   */
  void CEffectManagerImpl::Tick()
  {
    // Keep iteration semantics from the binary: capture next before invoking
    // effect code so list mutation during callback remains safe.
    TDatListItem<IEffect, void>* node = mActiveEffects.mNext;
    while (node != &mActiveEffects) {
      TDatListItem<IEffect, void>* const current = node;
      node = node->mNext;
      IEffect::ManagerList::owner_from_member<IEffect, IEffect::ManagerListNode, &IEffect::mManagerListNode>(current)
        ->OnTick();
    }
  }

  /**
   * Address: 0x0066B570 (FUN_0066B570, Moho::CEffectManagerImpl::PurgeDestroyedEffects)
   */
  void CEffectManagerImpl::PurgeDestroyedEffects()
  {
    while (!mDestroyedEffects.empty()) {
      IEffect* const effect = IEffect::ManagerList::owner_from_member<
        IEffect,
        IEffect::ManagerListNode,
        &IEffect::mManagerListNode>(mDestroyedEffects.mNext);
      delete effect;
    }
  }

  /**
   * Address: 0x0066B5A0 (FUN_0066B5A0, Moho::CEffectManagerImpl::CreateLightParticle)
   *
   * What it does:
   * Builds the particle texture paths, retains two counted particle-texture
   * lanes, and appends one `TLight` payload into the sim particle buffer when
   * the ramp texture lane is present.
   */
  void CEffectManagerImpl::CreateLightParticle(
    Wm3::Vector3<float> position,
    const msvc8::string& texturePrimary,
    const msvc8::string& textureSecondary,
    const float size,
    const float lifetime,
    const int armyIndex
  )
  {
    const msvc8::string primaryPath =
      BuildParticleTexturePath(texturePrimary, "/textures/particles/beam_white_01.dds");

    if (textureSecondary.empty()) {
      return;
    }

    const msvc8::string rampPath = BuildParticleTexturePath(textureSecondary, nullptr);

    SWorldParticle particle{};
    particle.mPos = position;
    particle.mDir = Wm3::Vector3<float>(0.0f, 0.0f, 0.0f);
    particle.mAccel = Wm3::Vector3<float>(0.0f, 0.0f, 0.0f);
    particle.mInterop = 0.0f;
    particle.mBlendMode = SWorldParticle::BlendMode::Mode3;
    particle.mLifetime = lifetime;
    particle.mBeginSize = size;
    particle.mEndSize = size;
    particle.mTypeTag.assign_owned("TLight");
    particle.mArmyIndex = armyIndex;

    CParticleTexture* const primaryTexture = new (std::nothrow) CParticleTexture(primaryPath.c_str());
    (void)AssignCountedParticleTexturePtr(&particle.mTexture, primaryTexture);

    CParticleTexture* const rampTexture = new (std::nothrow) CParticleTexture(rampPath.c_str());
    (void)AssignCountedParticleTexturePtr(&particle.mRampTexture, rampTexture);

    Sim* const sim = GetSim();
    if (sim == nullptr) {
      return;
    }

    SParticleBuffer* const submitBuffer = sim->GetParticleBuffer();
    if (submitBuffer == nullptr) {
      return;
    }

    AppendWorldParticleToVector(submitBuffer->mParticles, particle);
  }

  /**
   * Address: 0x006560E0 (FUN_006560E0, Moho::CEffectManagerImpl::CreateBeam)
   */
  IEffect* CEffectManagerImpl::CreateBeam(const RBeamBlueprint* const beamBlueprint, const int armyIndex)
  {
    CEfxBeam* const effect = new (std::nothrow) CEfxBeam();
    if (effect == nullptr) {
      return nullptr;
    }

    effect->mBlendMode = beamBlueprint != nullptr ? beamBlueprint->BlendMode : armyIndex;
    LinkActiveEffect(mActiveEffects, effect);

    if (!IsBlueprintEnabledForCurrentFidelity(beamBlueprint)) {
      DestroyEffect(effect);
    }

    return effect;
  }

  /**
   * Address: 0x00656020 (FUN_00656020, Moho::CEffectManagerImpl::CreateBeam)
   */
  IEffect* CEffectManagerImpl::CreateBeam(const SCreateBeamParams& params)
  {
    CEfxBeam* const effect = new (std::nothrow) CEfxBeam();
    if (effect == nullptr) {
      return nullptr;
    }

    if (params.mAttachEntity != nullptr) {
      if (params.mAttachBoneIndex == -1) {
        effect->SetEntity(params.mAttachEntity);
      } else {
        effect->SetBone(params.mAttachEntity, params.mAttachBoneIndex);
      }
    }

    effect->mBlendMode = params.mBlendMode;
    LinkActiveEffect(mActiveEffects, effect);
    return effect;
  }

  /**
   * Address: 0x006561C0 (FUN_006561C0, Moho::CEffectManagerImpl::CreateBeamEntityToEntity)
   */
  IEffect* CEffectManagerImpl::CreateBeamEntityToEntity(
    Entity* const sourceEntity,
    const int sourceBoneIndex,
    Entity* const targetEntity,
    const int targetBoneIndex,
    const RBeamBlueprint* const beamBlueprint,
    const int armyIndex
  )
  {
    CEfxBeam* const effect = new (std::nothrow) CEfxBeam();
    if (effect == nullptr) {
      return nullptr;
    }

    effect->mBlendMode = beamBlueprint != nullptr ? beamBlueprint->BlendMode : armyIndex;
    LinkActiveEffect(mActiveEffects, effect);

    const VTransform sourceTransform = sourceEntity->GetBoneWorldTransform(sourceBoneIndex);
    const float sourceLane[3] = {sourceTransform.pos_.x, sourceTransform.pos_.y, sourceTransform.pos_.z};

    const VTransform targetTransform = targetEntity->GetBoneWorldTransform(targetBoneIndex);
    const float targetLane[3] = {targetTransform.pos_.x, targetTransform.pos_.y, targetTransform.pos_.z};

    effect->SetNParam(0, sourceLane, 3);
    effect->SetNParam(3, targetLane, 3);

    if (!IsBlueprintEnabledForCurrentFidelity(beamBlueprint)) {
      DestroyEffect(effect);
    }

    return effect;
  }

  /**
   * Address: 0x00656340 (FUN_00656340, Moho::CEffectManagerImpl::AttachBeamEntityToEntity)
   */
  IEffect* CEffectManagerImpl::AttachBeamEntityToEntity(
    Entity* const sourceEntity,
    const int sourceBoneIndex,
    Entity* const targetEntity,
    const int targetBoneIndex,
    const RBeamBlueprint* const beamBlueprint,
    const int armyIndex
  )
  {
    CEfxBeam* const effect = new (std::nothrow) CEfxBeam();
    if (effect == nullptr) {
      return nullptr;
    }

    effect->mBlendMode = beamBlueprint != nullptr ? beamBlueprint->BlendMode : armyIndex;
    LinkActiveEffect(mActiveEffects, effect);

    effect->AttachEntityToEntity(sourceEntity, sourceBoneIndex, targetEntity, targetBoneIndex);

    if (!IsBlueprintEnabledForCurrentFidelity(beamBlueprint)) {
      DestroyEffect(effect);
    }

    return effect;
  }
} // namespace moho
