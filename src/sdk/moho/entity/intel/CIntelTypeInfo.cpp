#include "moho/entity/intel/CIntelTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/entity/intel/CIntel.h"
#include "moho/entity/intel/CIntelPosHandle.h"

#pragma init_seg(lib)

namespace
{
  template <class TTypeInfo>
  struct TypeInfoStorage
  {
    alignas(TTypeInfo) unsigned char bytes[sizeof(TTypeInfo)];
    bool constructed = false;
  };

  template <class TTypeInfo>
  [[nodiscard]] TTypeInfo& EnsureTypeInfo(TypeInfoStorage<TTypeInfo>& storage) noexcept
  {
    if (!storage.constructed) {
      new (storage.bytes) TTypeInfo();
      storage.constructed = true;
    }

    return *reinterpret_cast<TTypeInfo*>(storage.bytes);
  }

  template <class TTypeInfo>
  void DestroyTypeInfo(TypeInfoStorage<TTypeInfo>& storage) noexcept
  {
    if (!storage.constructed) {
      return;
    }

    reinterpret_cast<TTypeInfo*>(storage.bytes)->~TTypeInfo();
    storage.constructed = false;
  }

  TypeInfoStorage<moho::CIntelTypeInfo> gCIntelTypeInfoStorage{};

  [[nodiscard]] moho::CIntelTypeInfo& GetCIntelTypeInfo() noexcept
  {
    return EnsureTypeInfo(gCIntelTypeInfoStorage);
  }

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
   * Address: 0x0076E550 (FUN_0076E550, Moho::CIntelTypeInfo::CIntelTypeInfo)
   */
  CIntelTypeInfo::CIntelTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CIntel), this);
  }

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
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CIntelTypeInfo::NewRef,
      &CIntelTypeInfo::CtrRef,
      &CIntelTypeInfo::Delete,
      &CIntelTypeInfo::Destruct
    );
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

  /**
   * Address: 0x00C01D90 (FUN_00C01D90, cleanup_CIntelTypeInfo)
   *
   * What it does:
   * Runs process-exit teardown for startup `CIntelTypeInfo` storage.
   */
  void cleanup_CIntelTypeInfo()
  {
    DestroyTypeInfo(gCIntelTypeInfoStorage);
  }

  /**
   * Address: 0x00BDCBC0 (FUN_00BDCBC0, register_CIntelTypeInfo)
   *
   * What it does:
   * Builds startup `CIntelTypeInfo` storage and installs process-exit cleanup.
   */
  void register_CIntelTypeInfo()
  {
    (void)GetCIntelTypeInfo();
    (void)std::atexit(&cleanup_CIntelTypeInfo);
  }
} // namespace moho

namespace
{
  struct CIntelTypeInfoBootstrap
  {
    CIntelTypeInfoBootstrap()
    {
      moho::register_CIntelTypeInfo();
    }
  };

  [[maybe_unused]] CIntelTypeInfoBootstrap gCIntelTypeInfoBootstrap;
} // namespace
