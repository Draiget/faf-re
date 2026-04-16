#include "moho/sim/SThreatTypeInfo.h"

#include "moho/sim/CInfluenceMap.h"

namespace moho
{
  /**
   * Address: 0x007179B0 (FUN_007179B0, Moho::SThreatTypeInfo::SThreatTypeInfo)
   */
  SThreatTypeInfo::SThreatTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SThreat), this);
  }

  /**
   * Address: 0x00717A40 (FUN_00717A40, Moho::SThreatTypeInfo::dtr)
   */
  SThreatTypeInfo::~SThreatTypeInfo() = default;

  /**
   * Address: 0x00717A30 (FUN_00717A30, Moho::SThreatTypeInfo::GetName)
   */
  const char* SThreatTypeInfo::GetName() const
  {
    return "SThreat";
  }

  /**
   * Address: 0x00717A10 (FUN_00717A10, Moho::SThreatTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::SThreatTypeInfo::Init(gpg::RType *this);
   */
  void SThreatTypeInfo::Init()
  {
    size_ = sizeof(SThreat);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
