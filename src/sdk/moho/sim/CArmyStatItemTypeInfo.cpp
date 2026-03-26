#include "moho/sim/CArmyStatItemTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/misc/StatItem.h"
#include "moho/sim/CArmyStats.h"

namespace
{
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
    newRefFunc_ = &CArmyStatItemTypeInfo::NewRef;
    ctorRefFunc_ = &CArmyStatItemTypeInfo::CtrRef;
    deleteFunc_ = &CArmyStatItemTypeInfo::Delete;
    dtrFunc_ = &CArmyStatItemTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_StatItem(this);
    Finish();
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
