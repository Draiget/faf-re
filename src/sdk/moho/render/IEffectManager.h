#pragma once

#include <type_traits>

#include "gpg/core/containers/String.h"

namespace gpg
{
  class RType;
} // namespace gpg

namespace Wm3
{
  template <class T>
  struct Vector3;
} // namespace Wm3

namespace moho
{
  class Entity;
  class IEffect;
  class RBeamBlueprint;
  class SCreateBeamParams;
  class Sim;

  class IEffectManager
  {
  public:
    static gpg::RType* sType;

    [[nodiscard]]
    static gpg::RType* StaticGetClass();

  public:
    /**
     * Address: 0x0066B1F0 (FUN_0066B1F0, Moho::IEffectManager::dtr)
     *
     * What it does:
     * Implements deleting-style teardown for effect-manager interface pointers.
     */
    virtual ~IEffectManager();

    /**
     * Address: 0x0066B220 (FUN_0066B220, Moho::CEffectManagerImpl::GetSim)
     */
    [[nodiscard]]
    virtual Sim* GetSim() const = 0;

    /**
     * Address: 0x0065E220 (FUN_0065E220, Moho::CEffectManagerImpl::CreateEmitter)
     */
    virtual IEffect* CreateEmitter(Wm3::Vector3<float> position, const char* blueprintName, int armyIndex) = 0;

    /**
     * Address: 0x0065E390 (FUN_0065E390, Moho::CEffectManagerImpl::CreateAttachedEmitter)
     */
    virtual IEffect*
    CreateAttachedEmitter(Entity* entity, int boneIndex, const char* blueprintName, int armyIndex) = 0;

    /**
     * Address: 0x0065E520 (FUN_0065E520, Moho::CEffectManagerImpl::CreateEmitterAtBone)
     */
    virtual IEffect* CreateEmitterAtBone(Entity* entity, int boneIndex, const char* blueprintName, int armyIndex) = 0;

    /**
     * Address: 0x0065E6B0 (FUN_0065E6B0, Moho::CEffectManagerImpl::CreateEmitterAtEntity)
     */
    virtual IEffect* CreateEmitterAtEntity(Entity* entity, const char* blueprintName, int armyIndex) = 0;

    /**
     * Address: 0x0065E840 (FUN_0065E840, Moho::CEffectManagerImpl::CreateEmitterOnEntity)
     */
    virtual IEffect* CreateEmitterOnEntity(Entity* entity, const char* blueprintName, int armyIndex) = 0;

    /**
     * Address: 0x006560E0 (FUN_006560E0, Moho::CEffectManagerImpl::CreateBeam)
     */
    virtual IEffect* CreateBeam(const RBeamBlueprint* beamBlueprint, int armyIndex) = 0;

    /**
     * Address: 0x00656020 (FUN_00656020, Moho::CEffectManagerImpl::CreateBeam)
     */
    virtual IEffect* CreateBeam(const SCreateBeamParams& params) = 0;

    /**
     * Address: 0x006561C0 (FUN_006561C0, Moho::CEffectManagerImpl::CreateBeamEntityToEntity)
     */
    virtual IEffect* CreateBeamEntityToEntity(
      Entity* sourceEntity,
      int sourceBoneIndex,
      Entity* targetEntity,
      int targetBoneIndex,
      const RBeamBlueprint* beamBlueprint,
      int armyIndex
    ) = 0;

    /**
     * Address: 0x00656340 (FUN_00656340, Moho::CEffectManagerImpl::AttachBeamEntityToEntity)
     */
    virtual IEffect* AttachBeamEntityToEntity(
      Entity* sourceEntity,
      int sourceBoneIndex,
      Entity* targetEntity,
      int targetBoneIndex,
      const RBeamBlueprint* beamBlueprint,
      int armyIndex
    ) = 0;

    /**
     * Address: 0x006720F0 (FUN_006720F0, Moho::CEffectManagerImpl::CreateTrail)
     */
    virtual IEffect* CreateTrail(Entity* entity, int boneIndex, const char* blueprintName, int armyIndex) = 0;

    /**
     * Address: 0x0066B5A0 (FUN_0066B5A0, Moho::CEffectManagerImpl::CreateLightParticle)
     */
    virtual void CreateLightParticle(
      Wm3::Vector3<float> position,
      const msvc8::string& texturePrimary,
      const msvc8::string& textureSecondary,
      float lifeTime,
      float scale,
      int armyIndex
    ) = 0;

    /**
     * Address: 0x0066B4F0 (FUN_0066B4F0, Moho::CEffectManagerImpl::Tick)
     */
    virtual void Tick() = 0;

    /**
     * Address: 0x0066B230 (FUN_0066B230, Moho::CEffectManagerImpl::DestroyEffect)
     */
    virtual void DestroyEffect(IEffect* effect) = 0;

    /**
     * Address: 0x0066B570 (FUN_0066B570, Moho::CEffectManagerImpl::PurgeDestroyedEffects)
     */
    virtual void PurgeDestroyedEffects() = 0;
  };

  static_assert(sizeof(IEffectManager) == 0x4, "IEffectManager size must be 0x4");
  static_assert(std::is_polymorphic<IEffectManager>::value, "IEffectManager must remain polymorphic");
} // namespace moho
