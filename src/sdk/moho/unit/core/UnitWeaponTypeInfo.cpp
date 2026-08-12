#include "moho/unit/core/UnitWeaponTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/unit/core/UnitWeapon.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  using TypeInfo = moho::UnitWeaponTypeInfo;

  gpg::StaticTypeInfoStorage<TypeInfo> gUnitWeaponTypeInfoStorage{};

  [[nodiscard]] TypeInfo& AcquireUnitWeaponTypeInfo()
  {
    return gUnitWeaponTypeInfoStorage.Ensure();
  }

  /**
   * Returns the descriptor only if the static-init lane already built it.
   * The atexit cleanup below can run in a process that never touched
   * reflection, so it must not construct one on the way out.
   */
  [[nodiscard]] TypeInfo* PeekUnitWeaponTypeInfo() noexcept
  {
    if (!gUnitWeaponTypeInfoStorage.IsConstructed()) {
      return nullptr;
    }

    return &gUnitWeaponTypeInfoStorage.Ref();
  }

  template <class TTypeInfo>
  void ResetTypeInfoVectors(TTypeInfo& typeInfo) noexcept
  {
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x00BFE740 (FUN_00BFE740, cleanup lane)
   *
   * What it does:
   * Clears reflected field/base vectors for the `UnitWeaponTypeInfo` singleton.
   */
  void cleanup_UnitWeaponTypeInfo_00BFE740_Impl()
  {
    TypeInfo* const typeInfo = PeekUnitWeaponTypeInfo();
    if (!typeInfo) {
      return;
    }

    ResetTypeInfoVectors(*typeInfo);
  }

  void cleanup_UnitWeaponTypeInfo_AtExit()
  {
    cleanup_UnitWeaponTypeInfo_00BFE740_Impl();
  }

  /**
   * Address: 0x00BD88D0 (FUN_00BD88D0, startup registration + atexit cleanup)
   *
   * What it does:
   * Forces `UnitWeaponTypeInfo` construction and schedules exit cleanup.
   */
  int register_UnitWeaponTypeInfo_00BD88D0_Impl()
  {
    (void)AcquireUnitWeaponTypeInfo();
    return std::atexit(&cleanup_UnitWeaponTypeInfo_AtExit);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD88D0 (FUN_00BD88D0, startup registration + atexit cleanup)
   *
   * What it does:
   * Provider entry point for the phase-1 initializer walk: builds the
   * `UnitWeapon` descriptor and schedules its exit cleanup.
   */
  gpg::RType* preregister_UnitWeaponTypeInfo()
  {
    (void)register_UnitWeaponTypeInfo_00BD88D0_Impl();
    return &AcquireUnitWeaponTypeInfo();
  }
} // namespace moho

namespace moho
{
  /**
   * Address: 0x006D3FB0 (FUN_006D3FB0, ??0UnitWeaponTypeInfo@Moho@@QAE@@Z)
   */
  UnitWeaponTypeInfo::UnitWeaponTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(UnitWeapon), this);
  }

  /**
   * Address: 0x006D4050 (FUN_006D4050, Moho::UnitWeaponTypeInfo::dtr)
   */
  UnitWeaponTypeInfo::~UnitWeaponTypeInfo() = default;

  /**
   * Address: 0x006D4040 (FUN_006D4040, Moho::UnitWeaponTypeInfo::GetName)
   */
  const char* UnitWeaponTypeInfo::GetName() const
  {
    return "UnitWeapon";
  }

  /**
   * Address: 0x006D4010 (FUN_006D4010, Moho::UnitWeaponTypeInfo::Init)
   */
  void UnitWeaponTypeInfo::Init()
  {
    size_ = sizeof(UnitWeapon);
    AddBase_CScriptEvent(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006DD3D0 (FUN_006DD3D0, Moho::UnitWeaponTypeInfo::AddBase_CScriptEvent)
   */
  void UnitWeaponTypeInfo::AddBase_CScriptEvent(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return;
    }

    gpg::RType* baseType = CScriptEvent::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(CScriptEvent));
      CScriptEvent::sType = baseType;
    }

    gpg::RField baseField{};
    baseField.mName = baseType ? baseType->GetName() : "CScriptEvent";
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

} // namespace moho

// Phase-1 pre-registration: this descriptor was previously built by an
// ordinary namespace-scope bootstrap object, which the CRT runs in .CRT$XCU
// alongside the consumers that look it up. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_UnitWeaponTypeInfo_bd88d0, moho::preregister_UnitWeaponTypeInfo)
