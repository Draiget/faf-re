#include "moho/render/CEffectImpl.h"

#include <cstring>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/resource/CParticleTexture.h"

namespace
{
  void ReleaseParticleTextureRef(moho::CParticleTexture*& texture) noexcept
  {
    if (texture == nullptr) {
      return;
    }

    auto* const counted = static_cast<moho::CountedObject*>(texture);
    counted->ReleaseReferenceAtomic();
    texture = nullptr;
  }

  void RetainParticleTextureRef(moho::CParticleTexture* const texture) noexcept
  {
    if (texture == nullptr) {
      return;
    }

    auto* const counted = static_cast<moho::CountedObject*>(texture);
    counted->AddReferenceAtomic();
  }

  void AssignParticleTextureRef(moho::CParticleTexture*& slot, moho::CParticleTexture* const newTexture) noexcept
  {
    if (newTexture != nullptr) {
      RetainParticleTextureRef(newTexture);
    }
    ReleaseParticleTextureRef(slot);
    slot = newTexture;
  }

  void ClearStringRange(msvc8::string* it, const msvc8::string* const end) noexcept
  {
    while (it != end) {
      it->tidy(true, 0u);
      ++it;
    }
  }

  void ClearTextureRange(moho::CParticleTexture** it, moho::CParticleTexture** const end) noexcept
  {
    while (it != end) {
      ReleaseParticleTextureRef(*it);
      ++it;
    }
  }
} // namespace

namespace moho
{
  gpg::RType* CEffectImpl::sType = nullptr;

  CEffectImpl::CEffectImpl()
    : IEffect()
    , mUnknown44(0)
    , mParams()
    , mParticleTextures()
    , mStrings()
    , mEntityInfo(SEntAttachInfo::MakeDetached())
    , mNewAttachment(0)
    , mPad14D{0, 0, 0}
    , mMatrix(VMatrix4::Identity())
  {}

  /**
   * Address: 0x00659170 (FUN_00659170, Moho::CEffectImpl::dtr thunk)
   * Address: 0x00655BA0 (FUN_00655BA0, Moho::CEffectImpl::~CEffectImpl body)
   */
  CEffectImpl::~CEffectImpl()
  {
    mEntityInfo.mAttachTargetWeak.UnlinkFromOwnerChain();

    ClearStringRange(mStrings.start_, mStrings.end_);
    mStrings.ResetStorageToInline();

    ClearTextureRange(mParticleTextures.start_, mParticleTextures.end_);
    mParticleTextures.ResetStorageToInline();

    mParams.ResetStorageToInline();
  }

  /**
   * Address: 0x00654460 (FUN_00654460, Moho::CEffectImpl::OnInit)
   */
  void CEffectImpl::OnInit(const std::int32_t paramIndex, const char* const paramName)
  {
    if (paramName != nullptr && *paramName != '\0') {
      mStrings.start_[paramIndex].assign_owned(paramName);

      CParticleTexture* texture = new (std::nothrow) CParticleTexture(paramName);
      AssignParticleTextureRef(mParticleTextures.start_[paramIndex], texture);
      ReleaseParticleTextureRef(texture);
      return;
    }

    ReleaseParticleTextureRef(mParticleTextures.start_[paramIndex]);
  }

  /**
   * Address: 0x00654550 (FUN_00654550, Moho::CEffectImpl::GetStringParam)
   */
  msvc8::string* CEffectImpl::GetStringParam(const std::int32_t paramIndex)
  {
    return &mStrings.start_[paramIndex];
  }

  /**
   * Address: 0x00654570 (FUN_00654570, Moho::CEffectImpl::GetTextureParam)
   */
  CParticleTexture** CEffectImpl::GetTextureParam(CParticleTexture** const outTexture, const std::int32_t paramIndex)
  {
    CParticleTexture* const texture = mParticleTextures.start_[paramIndex];
    *outTexture = texture;
    RetainParticleTextureRef(texture);
    return outTexture;
  }

  /**
   * Address: 0x006545A0 (FUN_006545A0, Moho::CEffectImpl::GetFloatParam)
   */
  float CEffectImpl::GetFloatParam(const std::int32_t paramIndex)
  {
    return mParams.start_[paramIndex];
  }

  /**
   * Address: 0x006545B0 (FUN_006545B0, Moho::CEffectImpl::GetVectorParam)
   */
  Wm3::Vector3f* CEffectImpl::GetVectorParam(Wm3::Vector3f* const outValue, const std::int32_t paramIndex)
  {
    outValue->x = mParams.start_[paramIndex + 0];
    outValue->y = mParams.start_[paramIndex + 1];
    outValue->z = mParams.start_[paramIndex + 2];
    return outValue;
  }

  /**
   * Address: 0x006545E0 (FUN_006545E0, Moho::CEffectImpl::GetQuatParam)
   */
  Vector4f* CEffectImpl::GetQuatParam(Vector4f* const outValue, const std::int32_t paramIndex)
  {
    outValue->x = mParams.start_[paramIndex + 0];
    outValue->y = mParams.start_[paramIndex + 1];
    outValue->z = mParams.start_[paramIndex + 2];
    outValue->w = mParams.start_[paramIndex + 3];
    return outValue;
  }

  /**
   * Address: 0x006546E0 (FUN_006546E0, Moho::CEffectImpl::GetCurveParam)
   */
  std::int32_t CEffectImpl::GetCurveParam(const std::int32_t)
  {
    return 0;
  }

  /**
   * Address: 0x00654610 (FUN_00654610, Moho::CEffectImpl::SetFloatParam)
   */
  void CEffectImpl::SetFloatParam(const std::int32_t paramIndex, const float value)
  {
    mParams.start_[paramIndex] = value;
    Invalidate(paramIndex, 1);
  }

  /**
   * Address: 0x00654640 (FUN_00654640, Moho::CEffectImpl::SetVectorParam)
   */
  void CEffectImpl::SetVectorParam(const std::int32_t paramIndex, const Wm3::Vector3f* const value)
  {
    mParams.start_[paramIndex + 0] = value->x;
    mParams.start_[paramIndex + 1] = value->y;
    mParams.start_[paramIndex + 2] = value->z;
    Invalidate(paramIndex, 3);
  }

  /**
   * Address: 0x00654690 (FUN_00654690, Moho::CEffectImpl::SetNParam)
   */
  void CEffectImpl::SetNParam(const std::int32_t paramIndex, const float* const values, const std::int32_t valueCount)
  {
    std::memcpy(&mParams.start_[paramIndex], values, static_cast<std::size_t>(valueCount) * sizeof(float));
    Invalidate(paramIndex, valueCount);
  }

  /**
   * Address: 0x006546D0 (FUN_006546D0, Moho::CEffectImpl::SetCurveParam)
   */
  void CEffectImpl::SetCurveParam(const std::int32_t, const void*)
  {}

  /**
   * Address: 0x006592D0 (FUN_006592D0, Moho::CEffectImpl::SetEntity)
   */
  void CEffectImpl::SetEntity(Entity* const entity)
  {
    mNewAttachment = 1;
    mEntityInfo.mAttachTargetWeak.ResetFromObject(entity);
    entity->InitPositionHistory();
    Interpolate();
  }

  /**
   * Address: 0x00659280 (FUN_00659280, Moho::CEffectImpl::SetBone)
   */
  void CEffectImpl::SetBone(Entity* const entity, const std::int32_t boneIndex)
  {
    mNewAttachment = 1;
    mEntityInfo.mParentBoneIndex = boneIndex < 0 ? 0 : boneIndex;
    mEntityInfo.mAttachTargetWeak.ResetFromObject(entity);
    entity->InitPositionHistory();
    Interpolate();
  }

  /**
   * Address: 0x006543C0 (FUN_006543C0, Moho::IEffect::OnTick lane)
   */
  void CEffectImpl::OnTick()
  {}

  /**
   * Address: 0x00654430 (FUN_00654430, Moho::CEffectImpl::Invalidate)
   */
  void CEffectImpl::Invalidate(const std::int32_t, const std::int32_t)
  {}

  /**
   * Address: 0x00654440 (FUN_00654440, Moho::CEffectImpl::Invalidate2)
   */
  void CEffectImpl::Invalidate2(const std::int32_t)
  {}

  /**
   * Address: 0x00654450 (FUN_00654450, Moho::CEffectImpl::Interpolate)
   */
  void CEffectImpl::Interpolate()
  {}

  gpg::RType* CEffectImpl::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CEffectImpl));
    }
    return sType;
  }
} // namespace moho
