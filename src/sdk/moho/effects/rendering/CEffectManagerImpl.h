#pragma once

#include <cstddef>

#include "moho/containers/TDatList.h"
#include "moho/effects/rendering/IEffectManager.h"

namespace moho
{
  class CEffectManagerImpl : public IEffectManager
  {
  public:
    static gpg::RType* sType;

    [[nodiscard]]
    static gpg::RType* StaticGetClass();

  public:
    /**
     * Address: 0x0066B3E0 (FUN_0066B3E0, Moho::CEffectManagerImpl::CEffectManagerImpl)
     *
     * What it does:
     * Initializes one effect-manager implementation object by binding the
     * owning `Sim` lane and self-linking both intrusive effect lists.
     */
    explicit CEffectManagerImpl(Sim* sim);

    /**
     * Address: 0x0066B400 (FUN_0066B400, Moho::CEffectManagerImpl::dtr thunk)
     * Address: 0x0066B450 (FUN_0066B450, Moho::CEffectManagerImpl::~CEffectManagerImpl body)
     */
    ~CEffectManagerImpl() override;

    /**
     * Address: 0x0066B220 (FUN_0066B220, Moho::CEffectManagerImpl::GetSim)
     */
    [[nodiscard]]
    Sim* GetSim() const override;

    /**
     * Address: 0x0065E220 (FUN_0065E220, Moho::CEffectManagerImpl::CreateEmitter)
     *
     * What it does:
     * Spawns one emitter-style effect at one world-space position and links it
     * into the active manager list.
     */
    IEffect* CreateEmitter(Wm3::Vector3<float> position, const char* blueprintName, int armyIndex) override;

    /**
     * Address: 0x0065E390 (FUN_0065E390, Moho::CEffectManagerImpl::CreateAttachedEmitter)
     *
     * What it does:
     * Spawns one emitter-style effect attached to an entity bone and links it
     * into the active manager list.
     */
    IEffect* CreateAttachedEmitter(Entity* entity, int boneIndex, const char* blueprintName, int armyIndex) override;

    /**
     * Address: 0x0065E520 (FUN_0065E520, Moho::CEffectManagerImpl::CreateEmitterAtBone)
     *
     * What it does:
     * Spawns one emitter-style effect at one entity bone world transform and
     * links it into the active manager list.
     */
    IEffect* CreateEmitterAtBone(Entity* entity, int boneIndex, const char* blueprintName, int armyIndex) override;

    /**
     * Address: 0x0065E6B0 (FUN_0065E6B0, Moho::CEffectManagerImpl::CreateEmitterAtEntity)
     *
     * What it does:
     * Spawns one emitter-style effect at one entity world position and links it
     * into the active manager list.
     */
    IEffect* CreateEmitterAtEntity(Entity* entity, const char* blueprintName, int armyIndex) override;

    /**
     * Address: 0x0065E840 (FUN_0065E840, Moho::CEffectManagerImpl::CreateEmitterOnEntity)
     *
     * What it does:
     * Spawns one emitter-style effect attached to one entity root and links it
     * into the active manager list.
     */
    IEffect* CreateEmitterOnEntity(Entity* entity, const char* blueprintName, int armyIndex) override;

    /**
     * Address: 0x006720F0 (FUN_006720F0, Moho::CEffectManagerImpl::CreateTrail)
     *
     * What it does:
     * Spawns one trail-style effect attached to an entity bone and links it
     * into the active manager list.
     */
    IEffect* CreateTrail(Entity* entity, int boneIndex, const char* blueprintName, int armyIndex) override;

    /**
     * Address: 0x0066B230 (FUN_0066B230, Moho::CEffectManagerImpl::DestroyEffect)
     *
     * What it does:
     * Moves one effect instance from its current manager list to the pending-destroy list.
     */
    void DestroyEffect(IEffect* effect) override;

    /**
     * Address: 0x0066B4F0 (FUN_0066B4F0, Moho::CEffectManagerImpl::Tick)
     *
     * What it does:
     * Runs per-frame update for all active effect objects.
     */
    void Tick() override;

    /**
     * Address: 0x0066B570 (FUN_0066B570, Moho::CEffectManagerImpl::PurgeDestroyedEffects)
     *
     * What it does:
     * Deletes and removes all effects that were queued for destruction.
     */
    void PurgeDestroyedEffects() override;

    /**
     * Address: 0x0066B5A0 (FUN_0066B5A0, Moho::CEffectManagerImpl::CreateLightParticle)
     *
     * What it does:
     * Builds one light-particle payload, binds the primary and ramp particle textures,
     * and appends the payload into the sim particle submit buffer when a ramp texture is present.
     */
    void CreateLightParticle(
      Wm3::Vector3<float> position,
      const msvc8::string& texturePrimary,
      const msvc8::string& textureSecondary,
      float size,
      float lifetime,
      int armyIndex
    ) override;

    /**
     * Address: 0x006560E0 (FUN_006560E0, Moho::CEffectManagerImpl::CreateBeam)
     *
     * What it does:
     * Spawns one beam effect from blueprint + army lane and links it into the
     * active manager list.
     */
    IEffect* CreateBeam(const RBeamBlueprint* beamBlueprint, int armyIndex) override;

    /**
     * Address: 0x00656020 (FUN_00656020, Moho::CEffectManagerImpl::CreateBeam)
     *
     * What it does:
     * Spawns one beam effect from packed create params and links it into the
     * active manager list.
     */
    IEffect* CreateBeam(const SCreateBeamParams& params) override;

    /**
     * Address: 0x006561C0 (FUN_006561C0, Moho::CEffectManagerImpl::CreateBeamEntityToEntity)
     *
     * What it does:
     * Spawns one beam effect, writes source/target world-point params from two
     * entity bones, and links it into the active manager list.
     */
    IEffect* CreateBeamEntityToEntity(
      Entity* sourceEntity,
      int sourceBoneIndex,
      Entity* targetEntity,
      int targetBoneIndex,
      const RBeamBlueprint* beamBlueprint,
      int armyIndex
    ) override;

    /**
     * Address: 0x00656340 (FUN_00656340, Moho::CEffectManagerImpl::AttachBeamEntityToEntity)
     *
     * What it does:
     * Spawns one beam effect attached to source and target entity-bone lanes
     * and links it into the active manager list.
     */
    IEffect* AttachBeamEntityToEntity(
      Entity* sourceEntity,
      int sourceBoneIndex,
      Entity* targetEntity,
      int targetBoneIndex,
      const RBeamBlueprint* beamBlueprint,
      int armyIndex
    ) override;

  public:
    Sim* mSim;                              // +0x04
    TDatList<IEffect, void> mActiveEffects;   // +0x08
    TDatList<IEffect, void> mDestroyedEffects; // +0x10
  };

  static_assert(offsetof(CEffectManagerImpl, mSim) == 0x04, "CEffectManagerImpl::mSim offset must be 0x04");
  static_assert(
    offsetof(CEffectManagerImpl, mActiveEffects) == 0x08, "CEffectManagerImpl::mActiveEffects offset must be 0x08"
  );
  static_assert(
    offsetof(CEffectManagerImpl, mDestroyedEffects) == 0x10,
    "CEffectManagerImpl::mDestroyedEffects offset must be 0x10"
  );
  static_assert(sizeof(CEffectManagerImpl) == 0x18, "CEffectManagerImpl size must be 0x18");
} // namespace moho
