#include "moho/sim/SimArmyTypeInfo.h"

#include "moho/sim/SimArmy.h"

namespace moho
{
  /**
   * Address: 0x006FDA00 (FUN_006FDA00, Moho::SimArmyTypeInfo::dtr)
   */
  SimArmyTypeInfo::~SimArmyTypeInfo() = default;

  /**
   * Address: 0x006FD9F0 (FUN_006FD9F0, Moho::SimArmyTypeInfo::GetName)
   */
  const char* SimArmyTypeInfo::GetName() const
  {
    return "SimArmy";
  }

  /**
   * Address: 0x006FD9D0 (FUN_006FD9D0, Moho::SimArmyTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::SimArmyTypeInfo::Init(gpg::RType *this);
   */
  void SimArmyTypeInfo::Init()
  {
    size_ = sizeof(SimArmy);
    gpg::RType::Init();
    AddBase_IArmy(this);
    Finish();
  }

  /**
   * Address: 0x00703E40 (FUN_00703E40, Moho::SimArmyTypeInfo::AddBase_IArmy)
   */
  void SimArmyTypeInfo::AddBase_IArmy(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = IArmy::StaticGetClass();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0x08;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace moho
