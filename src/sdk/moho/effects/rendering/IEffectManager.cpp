#include "moho/effects/rendering/IEffectManager.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  gpg::RType* IEffectManager::sType = nullptr;

  /**
   * Address: 0x006540D0 (FUN_006540D0, Moho::SBeamCreateParams::SBeamCreateParams)
   *
   * What it does:
   * Initializes one beam create payload with default attachment, geometry,
   * texture, transform, and blend-mode lanes.
   */
  SCreateBeamParams::SCreateBeamParams()
    : mAttachEntity(nullptr)
    , mAttachArmyIndex(-1)
    , mAttachBoneIndex(-1)
    , mStart(0.0f, 0.0f, 0.0f)
    , mEnd(0.0f, 0.0f, 0.0f)
    , mLifetime(1.0f)
    , mWidth(1.0f)
    , mTextureScale(1.0f)
    , mTexture()
    , mSpawnTransform{{1.0f, 1.0f, 1.0f, 0.0f}, Wm3::Vector3<float>(0.0f, 0.0f, 0.0f)}
    , mBlendMode(3)
  {}

  /**
   * Address: 0x0066B420 (FUN_0066B420, ??0IEffectManager@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes the base interface vtable pointer for effect-manager objects.
   */
  IEffectManager::IEffectManager() = default;

  gpg::RType* IEffectManager::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(IEffectManager));
    }
    return sType;
  }

  /**
   * Address: 0x0066B1E0 (FUN_0066B1E0, Moho::IEffectManager::~IEffectManager base lane)
   * Address: 0x0066B1F0 (FUN_0066B1F0, Moho::IEffectManager::dtr)
   */
  IEffectManager::~IEffectManager() = default;
} // namespace moho
