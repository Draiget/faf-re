#include "moho/sim/CInfluenceMapTypeInfo.h"

#include "moho/sim/CInfluenceMap.h"

namespace moho
{
  /**
   * Address: 0x00717520 (FUN_00717520, Moho::CInfluenceMapTypeInfo::dtr)
   */
  CInfluenceMapTypeInfo::~CInfluenceMapTypeInfo() = default;

  /**
   * Address: 0x00717510 (FUN_00717510, Moho::CInfluenceMapTypeInfo::GetName)
   */
  const char* CInfluenceMapTypeInfo::GetName() const
  {
    return "CInfluenceMap";
  }

  /**
   * Address: 0x007174F0 (FUN_007174F0, Moho::CInfluenceMapTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::CInfluenceMapTypeInfo::Init(gpg::RType *this);
   */
  void CInfluenceMapTypeInfo::Init()
  {
    size_ = sizeof(CInfluenceMap);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
