#include "moho/unit/CUnitMotionTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/unit/CUnitMotion.h"

namespace
{
  using TypeInfo = moho::CUnitMotionTypeInfo;

  alignas(TypeInfo) unsigned char gCUnitMotionTypeInfoStorage[sizeof(TypeInfo)];
  bool gCUnitMotionTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetCUnitMotionTypeInfo() noexcept
  {
    if (!gCUnitMotionTypeInfoConstructed) {
      new (gCUnitMotionTypeInfoStorage) TypeInfo();
      gCUnitMotionTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCUnitMotionTypeInfoStorage);
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitMotion::sType = nullptr;

  gpg::RType* CUnitMotion::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CUnitMotion));
    }
    return sType;
  }

  /**
   * Address: 0x006B77A0 (FUN_006B77A0, Moho::CUnitMotionTypeInfo::CUnitMotionTypeInfo)
   */
  CUnitMotionTypeInfo::CUnitMotionTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitMotion), this);
  }

  /**
   * Address: 0x006B7830 (FUN_006B7830, gpg::RType::~RType thunk owner)
   */
  CUnitMotionTypeInfo::~CUnitMotionTypeInfo() = default;

  /**
   * Address: 0x006B7820 (FUN_006B7820, Moho::CUnitMotionTypeInfo::GetName)
   */
  const char* CUnitMotionTypeInfo::GetName() const
  {
    return "CUnitMotion";
  }

  /**
   * Address: 0x006B7800 (FUN_006B7800, Moho::CUnitMotionTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall sub_6B7800(_DWORD *this);
   */
  void CUnitMotionTypeInfo::Init()
  {
    size_ = sizeof(CUnitMotion);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BFE010 (FUN_00BFE010, cleanup_CUnitMotionTypeInfo)
   *
   * What it does:
   * Releases process-exit CUnitMotionTypeInfo storage.
   */
  void cleanup_CUnitMotionTypeInfo()
  {
    if (!gCUnitMotionTypeInfoConstructed) {
      return;
    }

    GetCUnitMotionTypeInfo().~CUnitMotionTypeInfo();
    gCUnitMotionTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD7220 (FUN_00BD7220, register_CUnitMotionTypeInfo)
   *
   * What it does:
   * Forces CUnitMotionTypeInfo startup construction and registers process-exit
   * cleanup.
   */
  int register_CUnitMotionTypeInfo()
  {
    (void)GetCUnitMotionTypeInfo();
    return std::atexit(&cleanup_CUnitMotionTypeInfo);
  }
} // namespace moho

namespace
{
  struct CUnitMotionTypeInfoBootstrap
  {
    CUnitMotionTypeInfoBootstrap()
    {
      (void)moho::register_CUnitMotionTypeInfo();
    }
  };

  [[maybe_unused]] CUnitMotionTypeInfoBootstrap gCUnitMotionTypeInfoBootstrap;
} // namespace
