#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "gpg/core/containers/String.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class RType;
} // namespace gpg

namespace moho
{
  class Entity;
  class IEffect;
  struct RBeamBlueprint;
  class Sim;

  /**
   * Address: 0x006540D0 (FUN_006540D0, Moho::SBeamCreateParams::SBeamCreateParams)
   *
   * What it does:
   * Stores beam endpoint transform defaults used by beam-spawn payload lanes.
   */
  struct SCreateBeamTransform
  {
    std::array<float, 4> mOrientation; // +0x00
    Wm3::Vector3<float> mPosition; // +0x10
  };

  static_assert(offsetof(SCreateBeamTransform, mOrientation) == 0x00, "SCreateBeamTransform::mOrientation offset must be 0x00");
  static_assert(offsetof(SCreateBeamTransform, mPosition) == 0x10, "SCreateBeamTransform::mPosition offset must be 0x10");
  static_assert(sizeof(SCreateBeamTransform) == 0x1C, "SCreateBeamTransform size must be 0x1C");

  /**
   * Address: 0x00657170 (FUN_00657170, func_AddBeam_SimConFunc call payload)
   * Address: 0x00656020 (FUN_00656020, Moho::CEffectManagerImpl::CreateBeam)
   *
   * What it does:
   * Carries one beam-spawn request from sim-console command parsing into
   * `IEffectManager::CreateBeam`.
   *
   * Notes:
   * Color/aux lanes at `+0x4C..+0x64` are still partially unnamed pending full
   * CEfxBeam constructor lane recovery.
   */
  struct SCreateBeamParams
  {
    /**
     * Address: 0x006540D0 (FUN_006540D0, Moho::SBeamCreateParams::SBeamCreateParams)
     *
     * What it does:
     * Initializes one beam create payload with default attachment, geometry,
     * texture, transform, and blend-mode lanes.
     */
    SCreateBeamParams();

    Entity* mAttachEntity;                 // +0x00
    std::int32_t mAttachArmyIndex;         // +0x04
    std::int32_t mAttachBoneIndex;         // +0x08
    Wm3::Vector3<float> mStart;            // +0x0C
    Wm3::Vector3<float> mEnd;              // +0x18
    float mLifetime;                       // +0x24
    float mWidth;                          // +0x28
    float mTextureScale;                   // +0x2C
    msvc8::string mTexture;                // +0x30
    SCreateBeamTransform mSpawnTransform;  // +0x4C
    std::int32_t mBlendMode;               // +0x68
  };

  static_assert(offsetof(SCreateBeamParams, mAttachEntity) == 0x00, "SCreateBeamParams::mAttachEntity offset must be 0x00");
  static_assert(
    offsetof(SCreateBeamParams, mAttachArmyIndex) == 0x04,
    "SCreateBeamParams::mAttachArmyIndex offset must be 0x04"
  );
  static_assert(
    offsetof(SCreateBeamParams, mAttachBoneIndex) == 0x08,
    "SCreateBeamParams::mAttachBoneIndex offset must be 0x08"
  );
  static_assert(offsetof(SCreateBeamParams, mStart) == 0x0C, "SCreateBeamParams::mStart offset must be 0x0C");
  static_assert(offsetof(SCreateBeamParams, mEnd) == 0x18, "SCreateBeamParams::mEnd offset must be 0x18");
  static_assert(offsetof(SCreateBeamParams, mLifetime) == 0x24, "SCreateBeamParams::mLifetime offset must be 0x24");
  static_assert(offsetof(SCreateBeamParams, mWidth) == 0x28, "SCreateBeamParams::mWidth offset must be 0x28");
  static_assert(
    offsetof(SCreateBeamParams, mTextureScale) == 0x2C,
    "SCreateBeamParams::mTextureScale offset must be 0x2C"
  );
  static_assert(offsetof(SCreateBeamParams, mTexture) == 0x30, "SCreateBeamParams::mTexture offset must be 0x30");
  static_assert(
    offsetof(SCreateBeamParams, mSpawnTransform) == 0x4C,
    "SCreateBeamParams::mSpawnTransform offset must be 0x4C"
  );
  static_assert(offsetof(SCreateBeamParams, mBlendMode) == 0x68, "SCreateBeamParams::mBlendMode offset must be 0x68");

  class IEffectManager
  {
  public:
    static gpg::RType* sType;

    [[nodiscard]]
    static gpg::RType* StaticGetClass();

  protected:
    /**
     * Address: 0x0066B420 (FUN_0066B420, ??0IEffectManager@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes the interface base vtable for effect-manager ownership.
     */
    IEffectManager();

  public:
    /**
     * Address: 0x0066B1E0 (FUN_0066B1E0, Moho::IEffectManager::~IEffectManager base lane)
     * Address: 0x0066B1F0 (FUN_0066B1F0, Moho::IEffectManager::dtr)
     *
     * What it does:
     * Restores base vftable ownership in the non-deleting lane and performs
     * deleting-style teardown for interface pointers.
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
      float size,
      float lifetime,
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
