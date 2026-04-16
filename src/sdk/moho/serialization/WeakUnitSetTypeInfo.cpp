#include "moho/serialization/WeakUnitSetTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/entity/Entity.h"

namespace
{
  using TypeInfo = moho::WeakUnitSetTypeInfo;

  alignas(TypeInfo) unsigned char gWeakUnitSetTypeInfoStorage[sizeof(TypeInfo)];
  bool gWeakUnitSetTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireWeakUnitSetTypeInfo()
  {
    if (!gWeakUnitSetTypeInfoConstructed) {
      new (gWeakUnitSetTypeInfoStorage) TypeInfo();
      gWeakUnitSetTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gWeakUnitSetTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006D2B10 (FUN_006D2B10, sub_6D2B10)
   */
  WeakUnitSetTypeInfo::WeakUnitSetTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(WeakEntitySetTemplate<Unit>), this);
  }

  /**
   * Address: 0x006D2C00 (FUN_006D2C00, WeakUnitSetTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `WeakUnitSetTypeInfo`
   * instance while preserving outer storage ownership.
   */
  [[maybe_unused]] void DestroyWeakUnitSetTypeInfoBody(WeakUnitSetTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x006D2BA0 (FUN_006D2BA0, sub_6D2BA0)
   */
  WeakUnitSetTypeInfo::~WeakUnitSetTypeInfo()
  {
    DestroyWeakUnitSetTypeInfoBody(this);
  }

  /**
   * Address: 0x006D2B90 (FUN_006D2B90, sub_6D2B90)
   */
  const char* WeakUnitSetTypeInfo::GetName() const
  {
    return "WeakUnitSet";
  }

  /**
   * Address: 0x006D2FA0 (FUN_006D2FA0, sub_6D2FA0)
   * Address: 0x006D2C40 (FUN_006D2C40, sub_6D2C40)
   *
   * What it does:
   * Resolves `EntitySetTemplate<Unit>` RTTI and appends it as base type.
   */
  void WeakUnitSetTypeInfo::AddBase_UnitSet(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = EntitySetTemplate<Unit>::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(EntitySetTemplate<Unit>));
      EntitySetTemplate<Unit>::sType = baseType;
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
   * Address: 0x006D2B70 (FUN_006D2B70, sub_6D2B70)
   */
  void WeakUnitSetTypeInfo::Init()
  {
    size_ = sizeof(WeakEntitySetTemplate<Unit>);
    gpg::RType::Init();
    AddBase_UnitSet(this);
    Finish();
  }

  /**
   * Address: 0x00BFE480 (FUN_00BFE480, sub_BFE480)
   */
  void cleanup_WeakUnitSetTypeInfo()
  {
    if (!gWeakUnitSetTypeInfoConstructed) {
      return;
    }

    AcquireWeakUnitSetTypeInfo().~WeakUnitSetTypeInfo();
    gWeakUnitSetTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD84C0 (FUN_00BD84C0, sub_BD84C0)
   */
  int register_WeakUnitSetTypeInfo()
  {
    (void)AcquireWeakUnitSetTypeInfo();
    return std::atexit(&cleanup_WeakUnitSetTypeInfo);
  }
} // namespace moho

namespace
{
  struct WeakUnitSetTypeInfoBootstrap
  {
    WeakUnitSetTypeInfoBootstrap()
    {
      (void)moho::register_WeakUnitSetTypeInfo();
    }
  };

  WeakUnitSetTypeInfoBootstrap gWeakUnitSetTypeInfoBootstrap;
} // namespace
