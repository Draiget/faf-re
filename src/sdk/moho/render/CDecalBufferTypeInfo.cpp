#include "moho/render/CDecalBufferTypeInfo.h"

#include <new>

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
    newRefFunc_ = &NewRef_CDecalBuffer;
    ctorRefFunc_ = &CtrRef_CDecalBuffer;
    deleteFunc_ = &Delete_CDecalBuffer;
    dtrFunc_ = &Dtr_CDecalBuffer;
    Finish();
  }
} // namespace moho
