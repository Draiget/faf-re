#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/entity/SEntAttachInfo.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/IEffect.h"

namespace moho
{
  using CEffectParamArray = gpg::fastvector_n<float, 26>;
  using CEffectTextureArray = gpg::fastvector_n<CParticleTexture*, 2>;
  using CEffectStringArray = gpg::fastvector_n<msvc8::string, 2>;

  static_assert(sizeof(CEffectParamArray) == 0x78, "CEffectParamArray size must be 0x78");
  static_assert(sizeof(CEffectTextureArray) == 0x18, "CEffectTextureArray size must be 0x18");
  static_assert(sizeof(CEffectStringArray) == 0x48, "CEffectStringArray size must be 0x48");

  class CEffectImpl : public IEffect
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00659090 (FUN_00659090, Moho::CEffectImpl::CEffectImpl)
     *
     * What it does:
     * Initializes effect parameter inline vectors, detached entity attachment
     * state, and identity matrix defaults.
     */
    CEffectImpl();

    /**
     * Address: 0x00659170 (FUN_00659170, Moho::CEffectImpl::dtr thunk)
     * Address: 0x00655BA0 (FUN_00655BA0, Moho::CEffectImpl::~CEffectImpl body)
     */
    ~CEffectImpl() override;

    /**
     * Address: 0x00654460 (FUN_00654460, Moho::CEffectImpl::OnInit)
     */
    void OnInit(std::int32_t paramIndex, const char* paramName) override;

    /**
     * Address: 0x00654550 (FUN_00654550, Moho::CEffectImpl::GetStringParam)
     */
    msvc8::string* GetStringParam(std::int32_t paramIndex) override;

    /**
     * Address: 0x00654570 (FUN_00654570, Moho::CEffectImpl::GetTextureParam)
     */
    CParticleTexture** GetTextureParam(CParticleTexture** outTexture, std::int32_t paramIndex) override;

    /**
     * Address: 0x006545A0 (FUN_006545A0, Moho::CEffectImpl::GetFloatParam)
     */
    float GetFloatParam(std::int32_t paramIndex) override;

    /**
     * Address: 0x006545B0 (FUN_006545B0, Moho::CEffectImpl::GetVectorParam)
     */
    Wm3::Vector3f* GetVectorParam(Wm3::Vector3f* outValue, std::int32_t paramIndex) override;

    /**
     * Address: 0x006545E0 (FUN_006545E0, Moho::CEffectImpl::GetQuatParam)
     */
    Vector4f* GetQuatParam(Vector4f* outValue, std::int32_t paramIndex) override;

    /**
     * Address: 0x006546E0 (FUN_006546E0, Moho::CEffectImpl::GetCurveParam)
     */
    std::int32_t GetCurveParam(std::int32_t paramIndex) override;

    /**
     * Address: 0x00654610 (FUN_00654610, Moho::CEffectImpl::SetFloatParam)
     */
    void SetFloatParam(std::int32_t paramIndex, float value) override;

    /**
     * Address: 0x00654640 (FUN_00654640, Moho::CEffectImpl::SetVectorParam)
     */
    void SetVectorParam(std::int32_t paramIndex, const Wm3::Vector3f* value) override;

    /**
     * Address: 0x00654690 (FUN_00654690, Moho::CEffectImpl::SetNParam)
     */
    void SetNParam(std::int32_t paramIndex, const float* values, std::int32_t valueCount) override;

    /**
     * Address: 0x006546D0 (FUN_006546D0, Moho::CEffectImpl::SetCurveParam)
     */
    void SetCurveParam(std::int32_t paramIndex, const void* curveData) override;

    /**
     * Address: 0x006592D0 (FUN_006592D0, Moho::CEffectImpl::SetEntity)
     */
    void SetEntity(Entity* entity) override;

    /**
     * Address: 0x00659280 (FUN_00659280, Moho::CEffectImpl::SetBone)
     */
    void SetBone(Entity* entity, std::int32_t boneIndex) override;

    /**
     * Address: 0x006543C0 (FUN_006543C0, Moho::IEffect::OnTick lane)
     */
    void OnTick() override;

    /**
     * Address: 0x00654430 (FUN_00654430, Moho::CEffectImpl::Invalidate)
     */
    virtual void Invalidate(std::int32_t paramIndex, std::int32_t valueCount);

    /**
     * Address: 0x00654440 (FUN_00654440, Moho::CEffectImpl::Invalidate2)
     */
    virtual void Invalidate2(std::int32_t paramIndex);

    /**
     * Address: 0x00654450 (FUN_00654450, Moho::CEffectImpl::Interpolate)
     */
    virtual void Interpolate();

    /**
     * What it does:
     * Returns cached reflection descriptor for `CEffectImpl`.
     */
    [[nodiscard]]
    static gpg::RType* StaticGetClass();

  public:
    std::uint32_t mUnknown44;         // +0x44
    CEffectParamArray mParams;        // +0x48
    CEffectTextureArray mParticleTextures; // +0xC0
    CEffectStringArray mStrings;      // +0xD8
    SEntAttachInfo mEntityInfo;       // +0x120
    std::uint8_t mNewAttachment;      // +0x14C
    std::uint8_t mPad14D[0x03];       // +0x14D
    VMatrix4 mMatrix;                 // +0x150
  };

  static_assert(offsetof(CEffectImpl, mUnknown44) == 0x44, "CEffectImpl::mUnknown44 offset must be 0x44");
  static_assert(offsetof(CEffectImpl, mParams) == 0x48, "CEffectImpl::mParams offset must be 0x48");
  static_assert(offsetof(CEffectImpl, mParams.start_) == 0x48, "CEffectImpl::mParams.start_ offset must be 0x48");
  static_assert(offsetof(CEffectImpl, mParams.end_) == 0x4C, "CEffectImpl::mParams.end_ offset must be 0x4C");
  static_assert(offsetof(CEffectImpl, mParams.capacity_) == 0x50, "CEffectImpl::mParams.capacity_ offset must be 0x50");
  static_assert(
    offsetof(CEffectImpl, mParams.originalVec_) == 0x54, "CEffectImpl::mParams.originalVec_ offset must be 0x54"
  );
  static_assert(offsetof(CEffectImpl, mParams.inlineVec_) == 0x58, "CEffectImpl::mParams.inlineVec_ offset must be 0x58");
  static_assert(
    offsetof(CEffectImpl, mParticleTextures) == 0xC0, "CEffectImpl::mParticleTextures offset must be 0xC0"
  );
  static_assert(
    offsetof(CEffectImpl, mParticleTextures.inlineVec_) == 0xD0,
    "CEffectImpl::mParticleTextures.inlineVec_ offset must be 0xD0"
  );
  static_assert(offsetof(CEffectImpl, mStrings) == 0xD8, "CEffectImpl::mStrings offset must be 0xD8");
  static_assert(offsetof(CEffectImpl, mStrings.inlineVec_) == 0xE8, "CEffectImpl::mStrings.inlineVec_ offset must be 0xE8");
  static_assert(offsetof(CEffectImpl, mEntityInfo) == 0x120, "CEffectImpl::mEntityInfo offset must be 0x120");
  static_assert(offsetof(CEffectImpl, mNewAttachment) == 0x14C, "CEffectImpl::mNewAttachment offset must be 0x14C");
  static_assert(offsetof(CEffectImpl, mMatrix) == 0x150, "CEffectImpl::mMatrix offset must be 0x150");
  static_assert(sizeof(CEffectImpl) == 0x190, "CEffectImpl size must be 0x190");
} // namespace moho
