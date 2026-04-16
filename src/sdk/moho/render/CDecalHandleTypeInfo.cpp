#include "moho/render/CDecalHandleTypeInfo.h"

#include <new>

#include "moho/render/CDecalHandle.h"
#include "moho/script/CScriptObject.h"

namespace
{
  /**
   * Address: 0x0077C7F0 (FUN_0077C7F0, Moho::CDecalHandle::operator new)
   */
  gpg::RRef NewRef_CDecalHandle()
  {
    gpg::RRef out{};
    out.mObj = new (std::nothrow) moho::CDecalHandle();
    out.mType = moho::CDecalHandle::StaticGetClass();
    return out;
  }

  /**
   * Address: 0x0077C890 (FUN_0077C890)
   */
  gpg::RRef CtrRef_CDecalHandle(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CDecalHandle*>(objectStorage);
    if (object != nullptr) {
      new (object) moho::CDecalHandle();
    }

    gpg::RRef out{};
    out.mObj = object;
    out.mType = moho::CDecalHandle::StaticGetClass();
    return out;
  }

  /**
   * Address: 0x0077C870 (FUN_0077C870)
   */
  void Delete_CDecalHandle(void* const objectStorage)
  {
    delete static_cast<moho::CDecalHandle*>(objectStorage);
  }

  /**
   * Address: 0x0077C900 (FUN_0077C900)
   */
  void Dtr_CDecalHandle(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CDecalHandle*>(objectStorage);
    if (object != nullptr) {
      object->~CDecalHandle();
    }
  }

  /**
   * Address: 0x0077AB70 (FUN_0077AB70)
   *
   * What it does:
   * Binds `CDecalHandle` new/construct/delete/destruct callback lanes into
   * the reflected type callback slots.
   */
  [[maybe_unused]] moho::CDecalHandleTypeInfo* BindDecalHandleTypeCallbackSlots(
    moho::CDecalHandleTypeInfo* const typeInfo
  )
  {
    typeInfo->newRefFunc_ = &NewRef_CDecalHandle;
    typeInfo->ctorRefFunc_ = &CtrRef_CDecalHandle;
    typeInfo->deleteFunc_ = &Delete_CDecalHandle;
    typeInfo->dtrFunc_ = &Dtr_CDecalHandle;
    return typeInfo;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00779E40 (FUN_00779E40, Moho::CDecalHandleTypeInfo::CDecalHandleTypeInfo)
   */
  CDecalHandleTypeInfo::CDecalHandleTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CDecalHandle), this);
  }

  /**
   * Address: 0x00779EF0 (FUN_00779EF0, Moho::CDecalHandleTypeInfo::dtr)
   */
  CDecalHandleTypeInfo::~CDecalHandleTypeInfo() = default;

  /**
   * Address: 0x00779EE0 (FUN_00779EE0, Moho::CDecalHandleTypeInfo::GetName)
   */
  const char* CDecalHandleTypeInfo::GetName() const
  {
    return "CDecalHandle";
  }

  /**
   * Address: 0x00779EA0 (FUN_00779EA0, Moho::CDecalHandleTypeInfo::Init)
   */
  void CDecalHandleTypeInfo::Init()
  {
    size_ = sizeof(CDecalHandle);
    (void)BindDecalHandleTypeCallbackSlots(this);
    AddBase_CScriptObject(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0077D8B0 (FUN_0077D8B0, Moho::CDecalHandleTypeInfo::AddBase_CScriptObject)
   */
  void CDecalHandleTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CScriptObject::StaticGetClass();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace moho
