#include "moho/render/CEffectImplTypeInfo.h"

#include "moho/render/CEffectImpl.h"

namespace moho
{
  /**
   * Address: 0x006597F0 (FUN_006597F0, Moho::CEffectImplTypeInfo::dtr)
   */
  CEffectImplTypeInfo::~CEffectImplTypeInfo() = default;

  /**
   * Address: 0x006597E0 (FUN_006597E0, Moho::CEffectImplTypeInfo::GetName)
   */
  const char* CEffectImplTypeInfo::GetName() const
  {
    return "CEffectImpl";
  }

  /**
   * Address: 0x006597B0 (FUN_006597B0, Moho::CEffectImplTypeInfo::Init)
   */
  void CEffectImplTypeInfo::Init()
  {
    size_ = sizeof(CEffectImpl);
    AddBase_IEffect(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0065A750 (FUN_0065A750, Moho::CEffectImplTypeInfo::AddBase_IEffect)
   */
  void CEffectImplTypeInfo::AddBase_IEffect(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = IEffect::StaticGetClass();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace moho

