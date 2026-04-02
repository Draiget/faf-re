#include "moho/entity/intel/CIntelPosHandleTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

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

  TypeInfoStorage<moho::CIntelPosHandleTypeInfo> gCIntelPosHandleTypeInfoStorage{};

  [[nodiscard]] moho::CIntelPosHandleTypeInfo& GetCIntelPosHandleTypeInfo() noexcept
  {
    return EnsureTypeInfo(gCIntelPosHandleTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0076F040 (FUN_0076F040, Moho::CIntelPosHandleTypeInfo::CIntelPosHandleTypeInfo)
   */
  CIntelPosHandleTypeInfo::CIntelPosHandleTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CIntelPosHandle), this);
  }

  /**
   * Address: 0x0076F0D0 (FUN_0076F0D0, Moho::CIntelPosHandleTypeInfo::dtr)
   */
  CIntelPosHandleTypeInfo::~CIntelPosHandleTypeInfo() = default;

  /**
   * Address: 0x0076F0C0 (FUN_0076F0C0, Moho::CIntelPosHandleTypeInfo::GetName)
   */
  const char* CIntelPosHandleTypeInfo::GetName() const
  {
    return "CIntelPosHandle";
  }

  /**
   * Address: 0x0076F0A0 (FUN_0076F0A0, Moho::CIntelPosHandleTypeInfo::Init)
   */
  void CIntelPosHandleTypeInfo::Init()
  {
    size_ = sizeof(CIntelPosHandle);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00C01E40 (FUN_00C01E40, cleanup_CIntelPosHandleTypeInfo)
   *
   * What it does:
   * Runs process-exit teardown for startup `CIntelPosHandleTypeInfo` storage.
   */
  void cleanup_CIntelPosHandleTypeInfo()
  {
    DestroyTypeInfo(gCIntelPosHandleTypeInfoStorage);
  }

  /**
   * Address: 0x00BDCC90 (FUN_00BDCC90, register_CIntelPosHandleTypeInfo)
   *
   * What it does:
   * Builds startup `CIntelPosHandleTypeInfo` storage and installs process-exit
   * cleanup.
   */
  void register_CIntelPosHandleTypeInfo()
  {
    (void)GetCIntelPosHandleTypeInfo();
    (void)std::atexit(&cleanup_CIntelPosHandleTypeInfo);
  }
} // namespace moho

namespace
{
  struct CIntelPosHandleTypeInfoBootstrap
  {
    CIntelPosHandleTypeInfoBootstrap()
    {
      moho::register_CIntelPosHandleTypeInfo();
    }
  };

  [[maybe_unused]] CIntelPosHandleTypeInfoBootstrap gCIntelPosHandleTypeInfoBootstrap;
} // namespace
