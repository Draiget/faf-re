#include "moho/serialization/CWeaponAttributesTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/unit/core/CWeaponAttributes.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  using TypeInfo = moho::CWeaponAttributesTypeInfo;

  gpg::StaticTypeInfoStorage<TypeInfo> gCWeaponAttributesTypeInfoStorage{};

  [[nodiscard]] TypeInfo& AcquireCWeaponAttributesTypeInfo()
  {
    return gCWeaponAttributesTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x00BFE590 (FUN_00BFE590, typeinfo cleanup)
   *
   * What it does:
   * Destroys the static descriptor, releasing its reflected field/base vector
   * storage. FUN_00BD87B0 hands this to `atexit` as the descriptor's own
   * destructor. A process that never reached the static-init lane has nothing
   * to tear down, so this must not construct one on the way out.
   */
  void cleanup_CWeaponAttributesTypeInfo_00BFE590_Impl()
  {
    gCWeaponAttributesTypeInfoStorage.Destroy();
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

  // The `CWeaponAttributesSerializer` consumer (a `gpg::LookupRType` caller,
  // so it must run in phase 2) now registers itself through its own plain
  // global's dynamic initializer in CWeaponAttributesSerializer.cpp; the
  // descriptor it resolves is still published from phase 1 by
  // `moho::preregister_CWeaponAttributesTypeInfo` below.
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD87B0 (FUN_00BD87B0, startup registration + atexit cleanup)
   *
   * What it does:
   * Provider entry point for the phase-1 initializer walk: builds the
   * `CWeaponAttributes` descriptor through the FUN_006D3640 constructor -
   * which is what performs the `PreRegisterRType` - and schedules its exit
   * cleanup.
   */
  gpg::RType* preregister_CWeaponAttributesTypeInfo()
  {
    (void)register_CWeaponAttributesTypeInfo_00BD87B0_Impl();
    return &AcquireCWeaponAttributesTypeInfo();
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
