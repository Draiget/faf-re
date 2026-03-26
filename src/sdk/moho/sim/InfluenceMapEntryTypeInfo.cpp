#include "moho/sim/InfluenceMapEntryTypeInfo.h"

#include "moho/sim/CInfluenceMap.h"

namespace moho
{
  /**
   * Address: 0x00717840 (FUN_00717840, Moho::InfluenceMapEntryTypeInfo::dtr)
   */
  InfluenceMapEntryTypeInfo::~InfluenceMapEntryTypeInfo() = default;

  /**
   * Address: 0x00717830 (FUN_00717830, Moho::InfluenceMapEntryTypeInfo::GetName)
   */
  const char* InfluenceMapEntryTypeInfo::GetName() const
  {
    return "InfluenceMapEntry";
  }

  /**
   * Address: 0x00717810 (FUN_00717810, Moho::InfluenceMapEntryTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::InfluenceMapEntryTypeInfo::Init(gpg::RType *this);
   */
  void InfluenceMapEntryTypeInfo::Init()
  {
    size_ = sizeof(InfluenceMapEntry);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
