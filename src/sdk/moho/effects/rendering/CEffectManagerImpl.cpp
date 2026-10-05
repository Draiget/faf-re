#include "moho/effects/rendering/CEffectManagerImpl.h"

#include <cstdarg>
#include <cstdio>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/effects/rendering/CEfxBeam.h"
#include "moho/effects/rendering/CEfxEmitter.h"
#include "moho/effects/rendering/CEfxTrailEmitter.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/entity/Entity.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
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
#include "gpg/core/containers/ArchiveSerialization.h"


namespace
{
  // TEMPORARY PROBE SINK -- effects triage, delete when resolved.
  // gpg::Warnf reaches nothing until `/log <name>` installs a target, so the
  // probes below append here instead. The file lands beside the executable.
  void DiagLine(const char* const fmt, ...)
  {
    std::FILE* const sink = std::fopen("faf_diag.log", "a");
    if (sink == nullptr) {
      return;
    }
    std::va_list args;
    va_start(args, fmt);
    (void)std::vfprintf(sink, fmt, args);
    va_end(args);
    (void)std::fputc(0x0A, sink);
    (void)std::fclose(sink);
  }
} // namespace

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
    /**
     * `Render_ActiveEmitters` as `CEffectManagerImpl::Tick` binds it
     * (`sEngineStat_Render_ActiveEmitters`, 0x010C743C). Tick zeroes it and
     * every emitter that runs adds one, so it counts the emitters ticked in
     * the latest effect-manager tick.
     */
    StatItem* sEngineStatRenderActiveEmitters = nullptr;

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

      effect->ListLinkBefore(&activeEffects);
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

    /**
     * Address: 0x00659390 (FUN_00659390)
     *
     * What it does:
     * Fetches one entity bone world transform (local pose bone composed with
     * the entity's current transform) into the effect's world matrix and
     * advances interpolation once.
     *
     * Binary fidelity note: this lane writes ONLY `mMatrix` - the
     * quaternion-to-matrix helper (0x004EE980) builds the rotation from the
     * composed transform and stores its translation lane into `effect+0x150` -
     * and then tail-jumps `Interpolate` (vtable +0x50). There is no
     * `SetNParam(0, pos, 3)` here: that is the *entity* variant's shape
     * (0x00659300), which writes the position into param slot 0 and leaves the
     * matrix identity. `CEfxEmitter::Interpolate` computes
     * `mPos = mMatrix * params[0..2]`, and the blueprint ctor leaves slots 0..2
     * as the emitter's local (zero) offset, so the bone-position ring lands at
     * the bone's own world position. Writing the world position into the slot
     * *as well* made Interpolate transform the bone position by the bone
     * matrix - doubling the map coordinates and putting every
     * `CreateEmitterAtBone` emitter (mass-storage blinking lights most
     * visibly) high in the air, far from its unit.
     */
    void ApplyBoneTransformToEffect(CEffectImpl& effect, Entity* const entity, const int boneIndex)
    {
      const VTransform boneTransform = entity->GetBoneWorldTransform(boneIndex);
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
      // A quaternion followed by a position, 0x1C bytes: that is `VTransform`,
      // which is also exactly what `entity.mVarDat.mCurTransform` already is.
      static_assert(sizeof(VTransform) == 0x1C, "VTransform size must be 0x1C");
      static_assert(offsetof(VTransform, pos_) == 0x10, "VTransform::pos_ offset must be 0x10");

      const VTransform& stackLane = entity.mVarDat.mCurTransform;
      effect.SetNParam(0, &stackLane.pos_.x, 3);
      effect.Interpolate();
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
    Sim* const sim = GetSim();
    REmitterBlueprint* const blueprint = LookupEmitterBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create emitter as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    // The blueprint emitter ctor seeds the emit position + every blueprint param
    // (21 curves + 20 scalars + textures) and interpolates; constructing through
    // the base CEffectImpl ctor here would drop all of it. armyIndex is the
    // effect's script-object token, forwarded to the base effect.
    CEffectImpl* const effect =
      LinkActiveEffect(mActiveEffects, new (std::nothrow) CEfxEmitter(this, position, armyIndex, blueprint));
    if (effect == nullptr) {
      return nullptr;
    }

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
    Sim* const sim = GetSim();
    REmitterBlueprint* const blueprint = LookupEmitterBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create emitter as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    CEffectImpl* const effect = LinkActiveEffect(
      mActiveEffects,
      new (std::nothrow) CEfxEmitter(this, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f), armyIndex, blueprint));
    if (effect == nullptr) {
      return nullptr;
    }

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
    Sim* const sim = GetSim();
    REmitterBlueprint* const blueprint = LookupEmitterBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create emitter as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    CEffectImpl* const effect = LinkActiveEffect(
      mActiveEffects,
      new (std::nothrow) CEfxEmitter(this, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f), armyIndex, blueprint));
    if (effect == nullptr) {
      return nullptr;
    }

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
    Sim* const sim = GetSim();
    REmitterBlueprint* const blueprint = LookupEmitterBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create emitter as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    CEffectImpl* const effect = LinkActiveEffect(
      mActiveEffects,
      new (std::nothrow) CEfxEmitter(this, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f), armyIndex, blueprint));
    if (effect == nullptr) {
      return nullptr;
    }

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
    Sim* const sim = GetSim();
    REmitterBlueprint* const blueprint = LookupEmitterBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create emitter as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    CEffectImpl* const effect = LinkActiveEffect(
      mActiveEffects,
      new (std::nothrow) CEfxEmitter(this, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f), armyIndex, blueprint));
    if (effect == nullptr) {
      return nullptr;
    }

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
    Sim* const sim = GetSim();
    RTrailBlueprint* const blueprint = LookupTrailBlueprint(sim, blueprintName);
    if (blueprintName != nullptr && blueprint == nullptr) {
      gpg::Warnf("Failed to create trail as you passed in an invalid blueprint name %s.", blueprintName);
      return nullptr;
    }

    // The binary seeds the trail emitter from a zeroed initial emit position and
    // relies on the blueprint ctor to publish lifetime/length/textures + scale.
    const float initialPosition[3] = {0.0f, 0.0f, 0.0f};
    CEfxTrailEmitter* const effect =
      new (std::nothrow) CEfxTrailEmitter(this, initialPosition, blueprint, armyIndex);
    if (effect == nullptr) {
      return nullptr;
    }
    LinkActiveEffect(mActiveEffects, effect);

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

    effect->ListLinkBefore(&mDestroyedEffects);
  }

  /**
   * Address: 0x0066B4F0 (FUN_0066B4F0, Moho::CEffectManagerImpl::Tick)
   *
   * What it does:
   * Zeroes `Render_ActiveEmitters` (the CAS loop at 0x0066B528, `SetInt`
   * inlined), then ticks every active effect.
   */
  void CEffectManagerImpl::Tick()
  {
    if (sEngineStatRenderActiveEmitters == nullptr) {
      sEngineStatRenderActiveEmitters = GetEngineStats()->GetItem("Render_ActiveEmitters", true);
      (void)sEngineStatRenderActiveEmitters->Release(0);
    }
    constexpr std::int32_t kNoEmitters = 0;
    (void)sEngineStatRenderActiveEmitters->SetInt(&kNoEmitters);

    // TEMPORARY PROBE -- effect-accumulation triage (assist lag), delete when
    // resolved. Active effect list growth without bound means leaks (beams
    // whose owning script threw before adding them to a TrashBag never get
    // destroyed); sampled every 100 ticks.
    {
      static std::uint32_t sSampleMod = 0;
      if ((++sSampleMod % 100u) == 0u) {
        static int sSampleCount = 0;
        if (sSampleCount++ < 600) {
          std::size_t activeCount = 0;
          for (IEffect* const effect : mActiveEffects.owners_safe()) {
            (void)effect;
            ++activeCount;
          }
          std::size_t destroyedCount = 0;
          for (IEffect* const effect : mDestroyedEffects.owners_safe()) {
            (void)effect;
            ++destroyedCount;
          }
          DiagLine("[EFXDIAG] EffectCount active=%zu destroyedPending=%zu", activeCount, destroyedCount);
        }
      }
    }

    // The successor is read before each OnTick, as the binary does: an effect
    // that destroys itself relinks into mDestroyedEffects mid-walk.
    for (IEffect* const effect : mActiveEffects.owners_safe()) {
      effect->OnTick();
    }
  }

  /**
   * Address: 0x0066B570 (FUN_0066B570, Moho::CEffectManagerImpl::PurgeDestroyedEffects)
   */
  void CEffectManagerImpl::PurgeDestroyedEffects()
  {
    while (!mDestroyedEffects.empty()) {
      delete mDestroyedEffects.ListGetNext();
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

    submitBuffer->mParticles.push_back(particle);
  }

  /**
   * Address: 0x006560E0 (FUN_006560E0, Moho::CEffectManagerImpl::CreateBeam)
   */
  IEffect* CEffectManagerImpl::CreateBeam(const RBeamBlueprint* const beamBlueprint, const int armyIndex)
  {
    CEfxBeam* const effect = new (std::nothrow) CEfxBeam(this, beamBlueprint, armyIndex);
    if (effect == nullptr) {
      return nullptr;
    }

    // Blend mode and every beam parameter are seeded by the blueprint ctor above.
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
    // The create-params ctor applies every beam render parameter (endpoints,
    // colour, length, thickness, UV shift, repeat rate, LOD cutoff, texture, and
    // blend mode) and runs Reset(); constructing through the default ctor here
    // would silently drop all of them.
    CEfxBeam* const effect = new (std::nothrow) CEfxBeam(this, params);
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
    CEfxBeam* const effect = new (std::nothrow) CEfxBeam(this, beamBlueprint, armyIndex);
    if (effect == nullptr) {
      return nullptr;
    }

    // Blend mode and every beam parameter are seeded by the blueprint ctor above.
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
    CEfxBeam* const effect = new (std::nothrow) CEfxBeam(this, beamBlueprint, armyIndex);
    if (effect == nullptr) {
      return nullptr;
    }

    // Blend mode and every beam parameter are seeded by the blueprint ctor above.
    LinkActiveEffect(mActiveEffects, effect);

    effect->AttachEntityToEntity(sourceEntity, sourceBoneIndex, targetEntity, targetBoneIndex);

    if (!IsBlueprintEnabledForCurrentFidelity(beamBlueprint)) {
      DestroyEffect(effect);
    }

    return effect;
  }
} // namespace moho

namespace moho
{
  void CEffectManagerImpl::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    Sim* sim = nullptr;
    const gpg::RRef owner{};
    archive.ReadPointer(&sim, &owner);
    result.SetUnowned(gpg::MakeRRef(new CEffectManagerImpl(sim)), 0u);
  }

  /**
   * Address: 0x0066BA60 (FUN_0066BA60)
   */
  void CEffectManagerImpl::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    archive.WritePointer(GetSim(), gpg::TrackedPointerState::Unowned, gpg::RRef{});
    result.SetUnowned(0u);
  }

  /**
   * `gpg::SerConstructHelper<CEffectManagerImpl>`, vtable 0x00E25E70.
   *
   * Address: 0x00BD45C0 (FUN_00BD45C0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFC030 (FUN_00BFC030 -- the global's destructor.)
   * Address: 0x0066C0E0 (FUN_0066C0E0 -- `Init`.)
   * Address: 0x0066BB40 (FUN_0066BB40 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x0066C280 (FUN_0066C280 -- `Delete`.)
   */
  struct CEffectManagerImplConstruct : gpg::SerConstructHelper<CEffectManagerImpl>
  {};

  /**
   * `gpg::SerSaveConstructHelper<CEffectManagerImpl>`, vtable 0x00E25E60.
   *
   * Address: 0x00BD4590 (FUN_00BD4590 -- constructs the global and registers its destructor.)
   * Address: 0x00BFC000 (FUN_00BFC000 -- the global's destructor.)
   * Address: 0x0066C060 (FUN_0066C060 -- `Init`.)
   * Address: 0x0066B9E0 (FUN_0066B9E0 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct CEffectManagerImplSaveConstruct : gpg::SerSaveConstructHelper<CEffectManagerImpl>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B3CB4 -- process-global `CEffectManagerImplConstruct` singleton.
  moho::CEffectManagerImplConstruct gCEffectManagerImplConstruct;

  // Address: 0x010B3CA4 -- process-global `CEffectManagerImplSaveConstruct` singleton.
  moho::CEffectManagerImplSaveConstruct gCEffectManagerImplSaveConstruct;
} // namespace
