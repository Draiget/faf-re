#include "moho/entity/intel/CIntelPosHandleTypeInfo.h"

#include "moho/entity/intel/CIntelPosHandle.h"

namespace moho
{
  /**
   * Address: 0x0076F0D0 (FUN_0076F0D0, Moho::CIntelPosHandleTypeInfo::dtr)
   */
  CIntelPosHandleTypeInfo::~CIntelPosHandleTypeInfo() = default;

  /**
   * Address: 0x0076F0C0 (FUN_0076F0C0, Moho::CIntelPosHandleTypeInfo::GetName)
   */
  const char* CIntelPosHandleTypeInfo::GetName() const
  {
    return "CIntelPosHandle";
  }

  /**
   * Address: 0x0076F0A0 (FUN_0076F0A0, Moho::CIntelPosHandleTypeInfo::Init)
   */
  void CIntelPosHandleTypeInfo::Init()
  {
    size_ = sizeof(CIntelPosHandle);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
