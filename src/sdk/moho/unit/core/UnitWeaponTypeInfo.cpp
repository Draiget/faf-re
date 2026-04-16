#include "moho/unit/core/UnitWeaponTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/unit/core/UnitWeapon.h"

#pragma init_seg(lib)

namespace
{
  using TypeInfo = moho::UnitWeaponTypeInfo;

  alignas(TypeInfo) unsigned char gUnitWeaponTypeInfoStorage[sizeof(TypeInfo)];
  bool gUnitWeaponTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireUnitWeaponTypeInfo()
  {
    if (!gUnitWeaponTypeInfoConstructed) {
      new (gUnitWeaponTypeInfoStorage) TypeInfo();
      gUnitWeaponTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gUnitWeaponTypeInfoStorage);
  }

  [[nodiscard]] TypeInfo* PeekUnitWeaponTypeInfo() noexcept
  {
    if (!gUnitWeaponTypeInfoConstructed) {
      return nullptr;
    }

    return reinterpret_cast<TypeInfo*>(gUnitWeaponTypeInfoStorage);
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

  struct UnitWeaponTypeInfoBootstrap
  {
    UnitWeaponTypeInfoBootstrap()
    {
      (void)register_UnitWeaponTypeInfo_00BD88D0_Impl();
    }
  };

  UnitWeaponTypeInfoBootstrap gUnitWeaponTypeInfoBootstrap;
} // namespace

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
