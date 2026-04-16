#include "moho/sim/InfluenceGridTypeInfo.h"

#include "moho/sim/CInfluenceMap.h"

namespace moho
{
  /**
   * Address: 0x00717BB0 (FUN_00717BB0, Moho::InfluenceGridTypeInfo::InfluenceGridTypeInfo)
   */
  InfluenceGridTypeInfo::InfluenceGridTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(InfluenceGrid), this);
  }

  /**
   * Address: 0x00717C40 (FUN_00717C40, Moho::InfluenceGridTypeInfo::dtr)
   */
  InfluenceGridTypeInfo::~InfluenceGridTypeInfo() = default;

  /**
   * Address: 0x00717C30 (FUN_00717C30, Moho::InfluenceGridTypeInfo::GetName)
   */
  const char* InfluenceGridTypeInfo::GetName() const
  {
    return "InfluenceGrid";
  }

  /**
   * Address: 0x00717C10 (FUN_00717C10, Moho::InfluenceGridTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::InfluenceGridTypeInfo::Init(gpg::RType *this);
   */
  void InfluenceGridTypeInfo::Init()
  {
    size_ = sizeof(InfluenceGrid);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
