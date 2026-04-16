#include "moho/ai/EFormationdStatusTypeInfo.h"

#include <cstdint>
#include <typeinfo>

namespace moho
{
  /**
   * Address: 0x00566090 (FUN_00566090, Moho::EFormationdStatusTypeInfo::EFormationdStatusTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EFormationdStatus` with the reflection registry.
   */
  EFormationdStatusTypeInfo::EFormationdStatusTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EFormationdStatus), this);
  }

  /**
   * Address: 0x00566150 (FUN_00566150, Moho::EFormationdStatusTypeInfo::dtr)
   */
  EFormationdStatusTypeInfo::~EFormationdStatusTypeInfo() = default;

  /**
   * Address: 0x00566140 (FUN_00566140, Moho::EFormationdStatusTypeInfo::GetName)
   */
  const char* EFormationdStatusTypeInfo::GetName() const
  {
    return "EFormationdStatus";
  }

  /**
   * Address: 0x005660F0 (FUN_005660F0, Moho::EFormationdStatusTypeInfo::Init)
   */
  void EFormationdStatusTypeInfo::Init()
  {
    size_ = sizeof(EFormationdStatus);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00566180 (FUN_00566180, Moho::EFormationdStatusTypeInfo::AddEnums)
   */
  void EFormationdStatusTypeInfo::AddEnums()
  {
    mPrefix = "FORMATIONSTATUS_";

    AddEnum(StripPrefix("FORMATIONSTATUS_FormationUpdated"), static_cast<std::int32_t>(FORMATIONSTATUS_FormationUpdated));
    AddEnum(StripPrefix("FORMATIONSTATUS_FormationAtGoal"), static_cast<std::int32_t>(FORMATIONSTATUS_FormationAtGoal));
  }
} // namespace moho
