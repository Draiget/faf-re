#include "moho/entity/intel/CIntelTypeInfo.h"

#include <new>

#include "moho/entity/intel/CIntel.h"
#include "moho/entity/intel/CIntelPosHandle.h"

namespace
{
  void DestroyHandleSlots(moho::CIntel* const intel)
  {
    if (!intel) {
      return;
    }

    for (std::size_t i = 0; i < moho::CIntel::kHandleCount; ++i) {
      moho::CIntelPosHandle* const handle = intel->mIntelHandles[i];
      if (handle) {
        handle->Destroy(1);
      }
    }
  }

  [[nodiscard]] gpg::RRef MakeCIntelRef(moho::CIntel* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = moho::CIntel::StaticGetClass();
    return out;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0076E600 (FUN_0076E600, Moho::CIntelTypeInfo::dtr)
   */
  CIntelTypeInfo::~CIntelTypeInfo() = default;

  /**
   * Address: 0x0076E5F0 (FUN_0076E5F0, Moho::CIntelTypeInfo::GetName)
   */
  const char* CIntelTypeInfo::GetName() const
  {
    return "CIntel";
  }

  /**
   * Address: 0x0076E5B0 (FUN_0076E5B0, Moho::CIntelTypeInfo::Init)
   */
  void CIntelTypeInfo::Init()
  {
    size_ = sizeof(CIntel);
    newRefFunc_ = &CIntelTypeInfo::NewRef;
    ctorRefFunc_ = &CIntelTypeInfo::CtrRef;
    deleteFunc_ = &CIntelTypeInfo::Delete;
    dtrFunc_ = &CIntelTypeInfo::Destruct;
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0076E8B0 (FUN_0076E8B0, Moho::CIntelTypeInfo::NewRef)
   */
  gpg::RRef CIntelTypeInfo::NewRef()
  {
    CIntel* const object = new (std::nothrow) CIntel();
    return MakeCIntelRef(object);
  }

  /**
   * Address: 0x0076E950 (FUN_0076E950, Moho::CIntelTypeInfo::CtrRef)
   */
  gpg::RRef CIntelTypeInfo::CtrRef(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<CIntel*>(objectPtr);
    if (object) {
      new (object) CIntel();
    }
    return MakeCIntelRef(object);
  }

  /**
   * Address: 0x0076E920 (FUN_0076E920, Moho::CIntelTypeInfo::Delete)
   */
  void CIntelTypeInfo::Delete(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<CIntel*>(objectPtr);
    if (!object) {
      return;
    }

    DestroyHandleSlots(object);
    ::operator delete(object);
  }

  /**
   * Address: 0x0076E9C0 (FUN_0076E9C0, Moho::CIntelTypeInfo::Destruct)
   */
  void CIntelTypeInfo::Destruct(void* const objectPtr)
  {
    DestroyHandleSlots(reinterpret_cast<CIntel*>(objectPtr));
  }
} // namespace moho
