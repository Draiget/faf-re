#include "moho/sim/CArmyStatsTypeInfo.h"

#include <typeinfo>

#include "moho/misc/Stats.h"
#include "moho/sim/CArmyStats.h"

namespace moho
{
  /**
   * Address: 0x0070DE80 (FUN_0070DE80, Moho::CArmyStatsTypeInfo::dtr)
   */
  CArmyStatsTypeInfo::~CArmyStatsTypeInfo() = default;

  /**
   * Address: 0x0070DE70 (FUN_0070DE70, Moho::CArmyStatsTypeInfo::GetName)
   */
  const char* CArmyStatsTypeInfo::GetName() const
  {
    return "CArmyStats";
  }

  /**
   * Address: 0x0070DE50 (FUN_0070DE50, Moho::CArmyStatsTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall Moho::CArmyStatsTypeInfo::Init(gpg::RType *this);
   */
  void CArmyStatsTypeInfo::Init()
  {
    size_ = sizeof(CArmyStats);
    gpg::RType::Init();
    AddBase_StatsCArmyStatItem(this);
    Finish();
  }

  /**
   * Address: 0x007125A0 (FUN_007125A0)
   */
  void CArmyStatsTypeInfo::AddBase_StatsCArmyStatItem(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = Stats<CArmyStatItem>::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(Stats<CArmyStatItem>));
      Stats<CArmyStatItem>::sType = baseType;
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
