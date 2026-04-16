#include "moho/entity/intel/CIntelCounterHandleTypeInfo.h"

#include <typeinfo>

#include "moho/entity/intel/CIntelCounterHandle.h"
#include "moho/entity/intel/CIntelPosHandle.h"

namespace moho
{
  /**
   * Address: 0x0076F520 (FUN_0076F520, Moho::CIntelCounterHandleTypeInfo::dtr)
   */
  CIntelCounterHandleTypeInfo::~CIntelCounterHandleTypeInfo() = default;

  /**
   * Address: 0x0076F510 (FUN_0076F510, Moho::CIntelCounterHandleTypeInfo::GetName)
   */
  const char* CIntelCounterHandleTypeInfo::GetName() const
  {
    return "CIntelCounterHandle";
  }

  /**
   * Address: 0x0076F4F0 (FUN_0076F4F0, Moho::CIntelCounterHandleTypeInfo::Init)
   */
  void CIntelCounterHandleTypeInfo::Init()
  {
    size_ = sizeof(CIntelCounterHandle);
    gpg::RType::Init();
    AddBase_CIntelPosHandle(this);
    Finish();
  }

  /**
   * Address: 0x0076F490 (FUN_0076F490, preregister_CIntelCounterHandleTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `moho::CIntelCounterHandle`.
   */
  [[nodiscard]] gpg::RType* preregister_CIntelCounterHandleTypeInfo()
  {
    static CIntelCounterHandleTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(CIntelCounterHandle), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x0076FD30 (FUN_0076FD30, Moho::CIntelCounterHandleTypeInfo::AddBase_CIntelPosHandle)
   */
  void CIntelCounterHandleTypeInfo::AddBase_CIntelPosHandle(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CIntelPosHandle::StaticGetClass();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace moho
