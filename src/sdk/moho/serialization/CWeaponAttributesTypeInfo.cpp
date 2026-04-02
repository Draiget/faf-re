#include "moho/serialization/CWeaponAttributesTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/serialization/CWeaponAttributesSerializer.h"
#include "moho/unit/core/CWeaponAttributes.h"

#pragma init_seg(lib)

namespace
{
  using TypeInfo = moho::CWeaponAttributesTypeInfo;

  alignas(TypeInfo) unsigned char gCWeaponAttributesTypeInfoStorage[sizeof(TypeInfo)];
  bool gCWeaponAttributesTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireCWeaponAttributesTypeInfo()
  {
    if (!gCWeaponAttributesTypeInfoConstructed) {
      new (gCWeaponAttributesTypeInfoStorage) TypeInfo();
      gCWeaponAttributesTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCWeaponAttributesTypeInfoStorage);
  }

  /**
   * Address: 0x00BFE590 (FUN_00BFE590, typeinfo cleanup)
   *
   * What it does:
   * Releases cached `CWeaponAttributesTypeInfo` vector storage at exit.
   */
  void cleanup_CWeaponAttributesTypeInfo_00BFE590_Impl()
  {
    if (!gCWeaponAttributesTypeInfoConstructed) {
      return;
    }

    AcquireCWeaponAttributesTypeInfo().~TypeInfo();
    gCWeaponAttributesTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD87B0 (FUN_00BD87B0, startup registration + atexit cleanup)
   *
   * What it does:
   * Forces `CWeaponAttributesTypeInfo` construction and schedules exit cleanup.
   */
  int register_CWeaponAttributesTypeInfo_00BD87B0_Impl()
  {
    (void)AcquireCWeaponAttributesTypeInfo();
    return std::atexit(&cleanup_CWeaponAttributesTypeInfo_00BFE590_Impl);
  }

  struct CWeaponAttributesTypeInfoBootstrap
  {
    CWeaponAttributesTypeInfoBootstrap()
    {
      (void)moho::register_CWeaponAttributesTypeInfo();
      (void)moho::register_CWeaponAttributesSerializer();
    }
  };

  CWeaponAttributesTypeInfoBootstrap gCWeaponAttributesTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x006D3640 (FUN_006D3640, ??0CWeaponAttributesTypeInfo@Moho@@QAE@@Z)
   */
  CWeaponAttributesTypeInfo::CWeaponAttributesTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CWeaponAttributes), this);
  }

  /**
   * Address: 0x006D36D0 (FUN_006D36D0, Moho::CWeaponAttributesTypeInfo::dtr)
   */
  CWeaponAttributesTypeInfo::~CWeaponAttributesTypeInfo()
  {
    fields_ = {};
    bases_ = {};
  }

  /**
   * Address: 0x006D36C0 (FUN_006D36C0, Moho::CWeaponAttributesTypeInfo::GetName)
   */
  const char* CWeaponAttributesTypeInfo::GetName() const
  {
    return "CWeaponAttributes";
  }

  /**
   * Address: 0x006D36A0 (FUN_006D36A0, Moho::CWeaponAttributesTypeInfo::Init)
   */
  void CWeaponAttributesTypeInfo::Init()
  {
    size_ = sizeof(CWeaponAttributes);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BFE590 (FUN_00BFE590, Moho::CWeaponAttributesTypeInfo::~CWeaponAttributesTypeInfo)
   */
  void cleanup_CWeaponAttributesTypeInfo()
  {
    cleanup_CWeaponAttributesTypeInfo_00BFE590_Impl();
  }

  /**
   * Address: 0x00BD87B0 (FUN_00BD87B0, register_CWeaponAttributesTypeInfo)
   */
  int register_CWeaponAttributesTypeInfo()
  {
    return register_CWeaponAttributesTypeInfo_00BD87B0_Impl();
  }
} // namespace moho
