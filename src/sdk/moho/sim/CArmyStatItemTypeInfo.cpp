#include "moho/sim/CArmyStatItemTypeInfo.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/misc/StatItem.h"
#include "moho/sim/CArmyStats.h"

namespace
{
  moho::CArmyStatItemTypeInfo gCArmyStatItemTypeInfo;

  [[nodiscard]] gpg::RRef MakeCArmyStatItemRef(moho::CArmyStatItem* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = moho::CArmyStatItem::StaticGetClass();
    return out;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0070B610 (FUN_0070B610, sub_70B610)
   *
   * IDA signature:
   * gpg::RType *sub_70B610();
   */
  CArmyStatItemTypeInfo::CArmyStatItemTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CArmyStatItem), this);
  }

  /**
   * Address: 0x00BDA100 (FUN_00BDA100, sub_BDA100)
   *
   * What it does:
   * Forces CArmyStatItem RTTI preregistration bootstrap and mirrors CRT
   * startup registration shape.
   */
  void register_CArmyStatItemTypeInfo()
  {
    (void)gCArmyStatItemTypeInfo;
  }

  /**
   * Address: 0x0070B6C0 (FUN_0070B6C0, Moho::CArmyStatItemTypeInfo::dtr)
   */
  CArmyStatItemTypeInfo::~CArmyStatItemTypeInfo() = default;

  /**
   * Address: 0x0070B6B0 (FUN_0070B6B0, Moho::CArmyStatItemTypeInfo::GetName)
   */
  const char* CArmyStatItemTypeInfo::GetName() const
  {
    return "CArmyStatItem";
  }

  /**
   * Address: 0x0070B670 (FUN_0070B670, Moho::CArmyStatItemTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall Moho::CArmyStatItemTypeInfo::Init(gpg::RType *this);
   */
  void CArmyStatItemTypeInfo::Init()
  {
    size_ = sizeof(CArmyStatItem);
    (void)AssignLifecycleCallbacks(this);
    gpg::RType::Init();
    AddBase_StatItem(this);
    Finish();
  }

  /**
   * Address: 0x0070EE90 (FUN_0070EE90)
   */
  gpg::RType* CArmyStatItemTypeInfo::AssignLifecycleCallbacks(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &CArmyStatItemTypeInfo::NewRef;
    typeInfo->ctorRefFunc_ = &CArmyStatItemTypeInfo::CtrRef;
    typeInfo->deleteFunc_ = &CArmyStatItemTypeInfo::Delete;
    typeInfo->dtrFunc_ = &CArmyStatItemTypeInfo::Destruct;
    return typeInfo;
  }

  /**
   * Address: 0x007111C0 (FUN_007111C0)
   */
  gpg::RRef CArmyStatItemTypeInfo::NewRef()
  {
    CArmyStatItem* const object = new (std::nothrow) CArmyStatItem("Root");
    return MakeCArmyStatItemRef(object);
  }

  /**
   * Address: 0x00711260 (FUN_00711260)
   */
  gpg::RRef CArmyStatItemTypeInfo::CtrRef(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<CArmyStatItem*>(objectPtr);
    if (object) {
      new (object) CArmyStatItem("Root");
    }
    return MakeCArmyStatItemRef(object);
  }

  /**
   * Address: 0x00711240 (FUN_00711240)
   */
  void CArmyStatItemTypeInfo::Delete(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<CArmyStatItem*>(objectPtr);
    delete object;
  }

  /**
   * Address: 0x007112E0 (FUN_007112E0)
   */
  void CArmyStatItemTypeInfo::Destruct(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<CArmyStatItem*>(objectPtr);
    if (!object) {
      return;
    }

    object->~CArmyStatItem();
  }

  /**
   * Address: 0x00712500 (FUN_00712500)
   */
  void CArmyStatItemTypeInfo::AddBase_StatItem(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = StatItem::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(StatItem));
      StatItem::sType = baseType;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00713BE0 (FUN_00713BE0, gpg::RRef_CArmyStatItem)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CArmyStatItem*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CArmyStatItem(gpg::RRef* const outRef, moho::CArmyStatItem* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RType* const baseType = moho::CArmyStatItem::StaticGetClass();
    outRef->mType = baseType;
    outRef->mObj = value;
    if (!value) {
      return outRef;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*value));
    } catch (...) {
      dynamicType = baseType;
    }

    if (!dynamicType || dynamicType == baseType) {
      return outRef;
    }

    std::int32_t baseOffset = 0;
    if (!dynamicType->IsDerivedFrom(baseType, &baseOffset)) {
      outRef->mType = dynamicType;
      outRef->mObj = value;
      return outRef;
    }

    outRef->mType = dynamicType;
    outRef->mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(value) - static_cast<std::uintptr_t>(baseOffset));
    return outRef;
  }

  /**
   * Address: 0x007129E0 (FUN_007129E0)
   *
   * What it does:
   * Packs one `RRef_CArmyStatItem` result into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_CArmyStatItem(
    gpg::RRef* const outRef,
    moho::CArmyStatItem* const value
  )
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef tmp{};
    (void)RRef_CArmyStatItem(&tmp, value);
    outRef->mObj = tmp.mObj;
    outRef->mType = tmp.mType;
    return outRef;
  }
} // namespace gpg

namespace
{
  struct CArmyStatItemTypeInfoBootstrap
  {
    CArmyStatItemTypeInfoBootstrap()
    {
      moho::register_CArmyStatItemTypeInfo();
    }
  };

  CArmyStatItemTypeInfoBootstrap gCArmyStatItemTypeInfoBootstrap;
} // namespace
