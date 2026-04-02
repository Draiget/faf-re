#include "moho/effects/rendering/IEffect.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"

namespace moho
{
  gpg::RType* IEffect::sType = nullptr;

  /**
   * Address: 0x00654220 (FUN_00654220, Moho::IEffect::GetClass)
   */
  gpg::RType* IEffect::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(IEffect));
    }
    return sType;
  }

  /**
   * Address: 0x00654220 (FUN_00654220, Moho::IEffect::GetClass)
   */
  gpg::RType* IEffect::GetClass() const
  {
    return StaticGetClass();
  }

  /**
   * Address: 0x00654240 (FUN_00654240, Moho::IEffect::GetDerivedObjectRef)
   */
  gpg::RRef IEffect::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x006543D0 (FUN_006543D0, Moho::IEffect::dtr)
   * Address: 0x00654180 (FUN_00654180, Moho::IEffect::~IEffect body)
   */
  IEffect::~IEffect()
  {
    mManagerListNode.ListUnlink();
  }

  /**
   * Address: 0x00654270 (FUN_00654270, Moho::IEffect::OnInit)
   */
  void IEffect::OnInit(const std::int32_t, const char*)
  {}

  /**
   * Address: 0x00654280 (FUN_00654280, Moho::IEffect::GetStringParam)
   */
  msvc8::string* IEffect::GetStringParam(const std::int32_t)
  {
    return nullptr;
  }

  /**
   * Address: 0x00654290 (FUN_00654290, Moho::IEffect::GetTextureParam)
   */
  CParticleTexture** IEffect::GetTextureParam(CParticleTexture** const outTexture, const std::int32_t)
  {
    *outTexture = nullptr;
    return outTexture;
  }

  /**
   * Address: 0x006542A0 (FUN_006542A0, Moho::IEffect::GetFloatParam)
   */
  float IEffect::GetFloatParam(const std::int32_t)
  {
    return 0.0f;
  }

  /**
   * Address: 0x006542B0 (FUN_006542B0, Moho::IEffect::GetVectorParam)
   */
  Wm3::Vector3f* IEffect::GetVectorParam(Wm3::Vector3f* const outValue, const std::int32_t)
  {
    *outValue = Wm3::Vector3f::Zero();
    return outValue;
  }

  /**
   * Address: 0x006542E0 (FUN_006542E0, Moho::IEffect::GetQuatParam)
   */
  Vector4f* IEffect::GetQuatParam(Vector4f* const outValue, const std::int32_t)
  {
    outValue->x = 0.0f;
    outValue->y = 0.0f;
    outValue->z = 0.0f;
    outValue->w = 0.0f;
    return outValue;
  }

  /**
   * Address: 0x00654350 (FUN_00654350, Moho::IEffect::GetCurveParam)
   */
  std::int32_t IEffect::GetCurveParam(const std::int32_t)
  {
    return 0;
  }

  /**
   * Address: 0x00654370 (FUN_00654370, Moho::IEffect::SetVectorParam)
   */
  void IEffect::SetVectorParam(const std::int32_t, const Wm3::Vector3f*)
  {}

  /**
   * Address: 0x00654360 (FUN_00654360, Moho::IEffect::SetFloatParam)
   */
  void IEffect::SetFloatParam(const std::int32_t, const float)
  {}

  /**
   * Address: 0x00654380 (FUN_00654380, Moho::IEffect::SetNParam)
   */
  void IEffect::SetNParam(const std::int32_t, const float*, const std::int32_t)
  {}

  /**
   * Address: 0x00654390 (FUN_00654390, Moho::IEffect::SetCurveParam)
   */
  void IEffect::SetCurveParam(const std::int32_t, const void*)
  {}

  /**
   * Address: 0x006543A0 (FUN_006543A0, Moho::IEffect::SetEntity)
   */
  void IEffect::SetEntity(Entity*)
  {}

  /**
   * Address: 0x006543B0 (FUN_006543B0, Moho::IEffect::SetBone)
   */
  void IEffect::SetBone(Entity*, const std::int32_t)
  {}

  /**
   * Address: 0x006543C0 (FUN_006543C0, Moho::IEffect::OnTick)
   */
  void IEffect::OnTick()
  {}
} // namespace moho
