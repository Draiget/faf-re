#include "moho/unit/core/UnitSetTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/entity/Entity.h"

namespace
{
  using TypeInfo = moho::UnitSetTypeInfo;

  alignas(TypeInfo) unsigned char gUnitSetTypeInfoStorage[sizeof(TypeInfo)];
  bool gUnitSetTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireUnitSetTypeInfo()
  {
    if (!gUnitSetTypeInfoConstructed) {
      new (gUnitSetTypeInfoStorage) TypeInfo();
      gUnitSetTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gUnitSetTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006D28C0 (FUN_006D28C0, sub_6D28C0)
   */
  UnitSetTypeInfo::UnitSetTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(EntitySetTemplate<Unit>), this);
  }

  /**
   * Address: 0x006D29B0 (FUN_006D29B0, UnitSetTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `UnitSetTypeInfo`
   * instance while preserving outer storage ownership.
   */
  [[maybe_unused]] void DestroyUnitSetTypeInfoBody(UnitSetTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x006D2950 (FUN_006D2950, sub_6D2950)
   */
  UnitSetTypeInfo::~UnitSetTypeInfo()
  {
    DestroyUnitSetTypeInfoBody(this);
  }

  /**
   * Address: 0x006D2940 (FUN_006D2940, sub_6D2940)
   */
  const char* UnitSetTypeInfo::GetName() const
  {
    return "UnitSet";
  }

  /**
   * Address: 0x006D2EC0 (FUN_006D2EC0, sub_6D2EC0)
   * Address: 0x006D29F0 (FUN_006D29F0, sub_6D29F0)
   *
   * What it does:
   * Resolves `EntitySetBase` RTTI and appends it as base type with zero offset.
   */
  void UnitSetTypeInfo::AddBase_EntitySetBaseVariant2(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = EntitySetBase::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(EntitySetBase));
      EntitySetBase::sType = baseType;
    }

    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(baseType != nullptr);
    if (!typeInfo || !baseType) {
      return;
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
   * Address: 0x006D2920 (FUN_006D2920, sub_6D2920)
   */
  void UnitSetTypeInfo::Init()
  {
    size_ = sizeof(EntitySetTemplate<Unit>);
    gpg::RType::Init();
    AddBase_EntitySetBaseVariant2(this);
    Finish();
  }

  /**
   * Address: 0x00BFE3F0 (FUN_00BFE3F0, sub_BFE3F0)
   */
  void cleanup_UnitSetTypeInfo()
  {
    if (!gUnitSetTypeInfoConstructed) {
      return;
    }

    AcquireUnitSetTypeInfo().~UnitSetTypeInfo();
    gUnitSetTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD8460 (FUN_00BD8460, sub_BD8460)
   */
  int register_UnitSetTypeInfo()
  {
    (void)AcquireUnitSetTypeInfo();
    return std::atexit(&cleanup_UnitSetTypeInfo);
  }
} // namespace moho

namespace
{
  struct UnitSetTypeInfoBootstrap
  {
    UnitSetTypeInfoBootstrap()
    {
      (void)moho::register_UnitSetTypeInfo();
    }
  };

  UnitSetTypeInfoBootstrap gUnitSetTypeInfoBootstrap;
} // namespace
