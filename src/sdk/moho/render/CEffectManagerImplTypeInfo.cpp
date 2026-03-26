#include "moho/render/CEffectManagerImplTypeInfo.h"

#include "moho/render/CEffectManagerImpl.h"
#include "moho/render/IEffectManager.h"

namespace moho
{
  /**
   * Address: 0x0066B330 (FUN_0066B330, Moho::CEffectManagerImplTypeInfo::dtr)
   *
   * IDA signature:
   * void **__thiscall sub_66B330(void **this, char a2);
   */
  CEffectManagerImplTypeInfo::~CEffectManagerImplTypeInfo() = default;

  /**
   * Address: 0x0066B320 (FUN_0066B320, Moho::CEffectManagerImplTypeInfo::GetName)
   *
   * IDA signature:
   * const char *sub_66B320();
   */
  const char* CEffectManagerImplTypeInfo::GetName() const
  {
    return "CEffectManagerImpl";
  }

  /**
   * Address: 0x0066B300 (FUN_0066B300, Moho::CEffectManagerImplTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall sub_66B300(gpg::RType *this);
   */
  void CEffectManagerImplTypeInfo::Init()
  {
    size_ = sizeof(CEffectManagerImpl);
    gpg::RType::Init();
    AddBase_IEffectManager(this);
    Finish();
  }

  /**
   * Address: 0x0066C220 (FUN_0066C220, Moho::CEffectManagerImplTypeInfo::AddBase_IEffectManager)
   *
   * IDA signature:
   * void __stdcall sub_66C220(gpg::RType *a1);
   */
  void CEffectManagerImplTypeInfo::AddBase_IEffectManager(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = IEffectManager::StaticGetClass();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace moho

