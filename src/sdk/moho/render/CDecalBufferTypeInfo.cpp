#include "moho/render/CDecalBufferTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/render/CDecalBuffer.h"

namespace
{
  /**
   * Address: 0x0077C090 (FUN_0077C090)
   */
  gpg::RRef NewRef_CDecalBuffer()
  {
    gpg::RRef out{};
    out.mObj = new (std::nothrow) moho::CDecalBuffer(nullptr);
    out.mType = moho::CDecalBuffer::StaticGetClass();
    return out;
  }

  /**
   * Address: 0x0077C130 (FUN_0077C130)
   */
  gpg::RRef CtrRef_CDecalBuffer(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CDecalBuffer*>(objectStorage);
    if (object != nullptr) {
      new (object) moho::CDecalBuffer(nullptr);
    }

    gpg::RRef out{};
    out.mObj = object;
    out.mType = moho::CDecalBuffer::StaticGetClass();
    return out;
  }

  /**
   * Address: 0x0077C110 (FUN_0077C110)
   */
  void Delete_CDecalBuffer(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CDecalBuffer*>(objectStorage);
    if (object != nullptr) {
      object->~CDecalBuffer();
      ::operator delete(object);
    }
  }

  /**
   * Address: 0x0077C1A0 (FUN_0077C1A0)
   */
  void Dtr_CDecalBuffer(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CDecalBuffer*>(objectStorage);
    if (object != nullptr) {
      object->~CDecalBuffer();
    }
  }

  /**
   * Address: 0x00779020 (FUN_00779020)
   *
   * What it does:
   * Binds `CDecalBuffer` new/construct/delete/destruct callback lanes into
   * the reflected type callback slots.
   */
  [[maybe_unused]] moho::CDecalBufferTypeInfo* BindDecalBufferTypeCallbackSlotsPrimary(
    moho::CDecalBufferTypeInfo* const typeInfo
  )
  {
    typeInfo->newRefFunc_ = &NewRef_CDecalBuffer;
    typeInfo->ctorRefFunc_ = &CtrRef_CDecalBuffer;
    typeInfo->deleteFunc_ = &Delete_CDecalBuffer;
    typeInfo->dtrFunc_ = &Dtr_CDecalBuffer;
    return typeInfo;
  }

  /**
   * Address: 0x0077A740 (FUN_0077A740)
   *
   * What it does:
   * Secondary callback-slot binder for `CDecalBuffer` reflected type
   * lifecycle lanes.
   */
  [[maybe_unused]] moho::CDecalBufferTypeInfo* BindDecalBufferTypeCallbackSlotsSecondary(
    moho::CDecalBufferTypeInfo* const typeInfo
  )
  {
    return BindDecalBufferTypeCallbackSlotsPrimary(typeInfo);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00778F80 (FUN_00778F80, Moho::CDecalBufferTypeInfo::dtr)
   */
  CDecalBufferTypeInfo::~CDecalBufferTypeInfo() = default;

  /**
   * Address: 0x00778F70 (FUN_00778F70, Moho::CDecalBufferTypeInfo::GetName)
   */
  const char* CDecalBufferTypeInfo::GetName() const
  {
    return "CDecalBuffer";
  }

  /**
   * Address: 0x00778F30 (FUN_00778F30, Moho::CDecalBufferTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall Moho::CDecalBufferTypeInfo::Init(_DWORD *this);
   */
  void CDecalBufferTypeInfo::Init()
  {
    size_ = sizeof(CDecalBuffer);
    gpg::RType::Init();
    (void)BindDecalBufferTypeCallbackSlotsPrimary(this);
    Finish();
  }

  /**
   * Address: 0x00778ED0 (FUN_00778ED0, preregister_CDecalBufferTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `moho::CDecalBuffer`.
   */
  [[nodiscard]] gpg::RType* preregister_CDecalBufferTypeInfo()
  {
    static CDecalBufferTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(CDecalBuffer), &typeInfo);
    return &typeInfo;
  }
} // namespace moho
