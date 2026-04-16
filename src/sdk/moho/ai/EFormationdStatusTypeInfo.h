#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EFormationdStatus : std::int32_t
  {
    FORMATIONSTATUS_FormationUpdated = 0,
    FORMATIONSTATUS_FormationAtGoal = 1,
  };

  static_assert(sizeof(EFormationdStatus) == 0x4, "EFormationdStatus size must be 0x4");

  class EFormationdStatusTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00566090 (FUN_00566090, Moho::EFormationdStatusTypeInfo::EFormationdStatusTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EFormationdStatus` with the reflection registry.
     */
    EFormationdStatusTypeInfo();

    /**
     * Address: 0x00566150 (FUN_00566150, Moho::EFormationdStatusTypeInfo::dtr)
     */
    ~EFormationdStatusTypeInfo() override;

    /**
     * Address: 0x00566140 (FUN_00566140, Moho::EFormationdStatusTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005660F0 (FUN_005660F0, Moho::EFormationdStatusTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00566180 (FUN_00566180, Moho::EFormationdStatusTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EFormationdStatusTypeInfo) == 0x78, "EFormationdStatusTypeInfo size must be 0x78");
} // namespace moho
