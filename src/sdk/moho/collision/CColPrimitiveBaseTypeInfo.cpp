#include "moho/collision/CColPrimitiveBaseTypeInfo.h"

#include "moho/collision/CColPrimitiveBase.h"

namespace moho
{
  /**
   * Address: 0x004FE590 (FUN_004FE590, Moho::CColPrimitiveBaseTypeInfo::dtr)
   */
  CColPrimitiveBaseTypeInfo::~CColPrimitiveBaseTypeInfo() = default;

  /**
   * Address: 0x004FE580 (FUN_004FE580, Moho::CColPrimitiveBaseTypeInfo::GetName)
   */
  const char* CColPrimitiveBaseTypeInfo::GetName() const
  {
    return "CColPrimitiveBase";
  }

  /**
   * Address: 0x004FE560 (FUN_004FE560, Moho::CColPrimitiveBaseTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::CColPrimitiveBaseTypeInfo::Init(gpg::RType *this);
   */
  void CColPrimitiveBaseTypeInfo::Init()
  {
    size_ = sizeof(CColPrimitiveBase);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

