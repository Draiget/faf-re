#include "moho/unit/core/UnitWeaponTypeInfo.h"

#include <typeinfo>

#include "moho/unit/core/UnitWeapon.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::UnitWeaponTypeInfo;

  /**
   * Address: 0x00BFE740 (FUN_00BFE740, atexit destructor of the UnitWeaponTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireUnitWeaponTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD88D0 (FUN_00BD88D0, startup registration)
   *
   * What it does:
   * Provider entry point for the phase-1 initializer walk: builds the
   * `UnitWeapon` descriptor.
   */
  gpg::RType* preregister_UnitWeaponTypeInfo()
  {
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
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

} // namespace moho

// Phase-1 pre-registration: this descriptor was previously built by an
// ordinary namespace-scope bootstrap object, which the CRT runs in .CRT$XCU
// alongside the consumers that look it up. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_UnitWeaponTypeInfo_bd88d0, moho::preregister_UnitWeaponTypeInfo)
