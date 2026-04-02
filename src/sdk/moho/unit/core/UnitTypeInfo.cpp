#include "moho/unit/core/UnitTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/entity/Entity.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

namespace
{
  using TypeInfo = moho::UnitTypeInfo;

  alignas(TypeInfo) unsigned char gUnitTypeInfoStorage[sizeof(TypeInfo)];
  bool gUnitTypeInfoConstructed = false;
  gpg::RType* gEntityType = nullptr;
  gpg::RType* gIUnitType = nullptr;

  void ResetTypeInfoVectors(TypeInfo& typeInfo) noexcept
  {
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  [[nodiscard]] TypeInfo& AcquireUnitTypeInfo()
  {
    if (!gUnitTypeInfoConstructed) {
      new (gUnitTypeInfoStorage) TypeInfo();
      gUnitTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gUnitTypeInfoStorage);
  }

  struct UnitTypeInfoBootstrap
  {
    UnitTypeInfoBootstrap()
    {
      (void)moho::register_UnitTypeInfo();
    }
  };

  [[maybe_unused]] UnitTypeInfoBootstrap gUnitTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x006AD090 (FUN_006AD090, Moho::UnitTypeInfo::UnitTypeInfo)
   *
   * What it does:
   * Preregisters RTTI metadata for `Unit` and prepares the reflected type
   * descriptor for later startup initialization.
   */
  UnitTypeInfo::UnitTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Unit), this);
  }

  /**
   * Address: 0x006AD130 (FUN_006AD130, Moho::UnitTypeInfo::dtr)
   *
   * What it does:
   * Releases reflected base/field vectors for this descriptor.
   */
  UnitTypeInfo::~UnitTypeInfo()
  {
    ResetTypeInfoVectors(*this);
  }

  /**
   * Address: 0x006AD120 (FUN_006AD120, Moho::UnitTypeInfo::GetName)
   *
   * What it does:
   * Returns the reflected type name for `Unit`.
   */
  const char* UnitTypeInfo::GetName() const
  {
    return "Unit";
  }

  /**
   * Address: 0x006AD0F0 (FUN_006AD0F0, Moho::UnitTypeInfo::Init)
   *
   * What it does:
   * Sets reflected size/version metadata, adds `Entity` and `IUnit` bases,
   * and finalizes the RTTI descriptor.
   */
  void UnitTypeInfo::Init()
  {
    size_ = sizeof(Unit);
    AddBase_Entity(this);
    gpg::RType::Init();
    Version(1);
    AddBase_IUnit(this);
    Finish();
  }

  /**
   * Address: 0x006B0F50 (FUN_006B0F50, Moho::UnitTypeInfo::AddBase_Entity)
   *
   * What it does:
   * Adds `Entity` as a reflected base at offset `8`.
   */
  void UnitTypeInfo::AddBase_Entity(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = gEntityType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(Entity));
      gEntityType = baseType;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 8;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x006B0FB0 (FUN_006B0FB0, Moho::UnitTypeInfo::AddBase_IUnit)
   *
   * What it does:
   * Adds `IUnit` as a reflected base at offset `0`.
   */
  void UnitTypeInfo::AddBase_IUnit(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = gIUnitType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(IUnit));
      gIUnitType = baseType;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BFD970 (FUN_00BFD970, cleanup_UnitTypeInfo)
   *
   * What it does:
   * Releases global `UnitTypeInfo` reflection vectors during process exit.
   */
  void cleanup_UnitTypeInfo()
  {
    if (!gUnitTypeInfoConstructed) {
      return;
    }

    ResetTypeInfoVectors(AcquireUnitTypeInfo());
    gUnitTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD6AD0 (FUN_00BD6AD0, register_UnitTypeInfo)
   *
   * What it does:
   * Constructs the global `UnitTypeInfo` storage and registers exit cleanup.
   */
  void register_UnitTypeInfo()
  {
    (void)AcquireUnitTypeInfo();
    (void)std::atexit(&cleanup_UnitTypeInfo);
  }
} // namespace moho
