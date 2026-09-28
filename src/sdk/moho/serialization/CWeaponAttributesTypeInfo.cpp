#include "moho/serialization/CWeaponAttributesTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/unit/core/CWeaponAttributes.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CWeaponAttributesTypeInfo;

  /**
   * Address: 0x00BFE590 (FUN_00BFE590, atexit destructor of the CWeaponAttributesTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireCWeaponAttributesTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  // The `CWeaponAttributesSerializer` consumer (a `gpg::LookupRType` caller,
  // so it must run in phase 2) now registers itself through its own plain
  // global's dynamic initializer in CWeaponAttributesSerializer.cpp; the
  // descriptor it resolves is still published from phase 1 by
  // `moho::preregister_CWeaponAttributesTypeInfo` below.
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD87B0 (FUN_00BD87B0, register_CWeaponAttributesTypeInfo)
   *
   * What it does:
   * Provider entry point for the phase-1 initializer walk: builds the
   * `CWeaponAttributes` descriptor through the FUN_006D3640 constructor -
   * which is what performs the `PreRegisterRType`.
   */
  void preregister_CWeaponAttributesTypeInfo()
  {
    (void)AcquireCWeaponAttributesTypeInfo();
  }

  /**
   * Address: 0x006D3640 (FUN_006D3640, ??0CWeaponAttributesTypeInfo@Moho@@QAE@@Z)
   */
  CWeaponAttributesTypeInfo::CWeaponAttributesTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CWeaponAttributes), this);
  }

  /**
   * Address: 0x006D3730 (FUN_006D3730, CWeaponAttributesTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one
   * `CWeaponAttributesTypeInfo` instance while preserving outer storage
   * ownership.
   */
  void DestroyCWeaponAttributesTypeInfoBody(CWeaponAttributesTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x006D36D0 (FUN_006D36D0, Moho::CWeaponAttributesTypeInfo::dtr)
   */
  CWeaponAttributesTypeInfo::~CWeaponAttributesTypeInfo()
  {
    DestroyCWeaponAttributesTypeInfoBody(this);
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

} // namespace moho

// Phase-1 pre-registration: this descriptor was previously built by an
// ordinary namespace-scope bootstrap object, which the CRT runs in .CRT$XCU
// alongside moho::CWeaponAttributesSerializer's own dynamic initializer (see
// CWeaponAttributesSerializer.cpp) - the gpg::LookupRType consumer that
// depends on it. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_CWeaponAttributesTypeInfo_bd87b0, moho::preregister_CWeaponAttributesTypeInfo)
