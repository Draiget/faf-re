#include "moho/net/CLobbyTypeInfo.h"

#include "moho/net/CLobby.h"

namespace moho
{
  /**
   * Address: 0x007C08C0 (FUN_007C08C0, Moho::CLobbyTypeInfo::dtr)
   */
  CLobbyTypeInfo::~CLobbyTypeInfo() = default;

  /**
   * Address: 0x007C08B0 (FUN_007C08B0, Moho::CLobbyTypeInfo::GetName)
   *
   * IDA signature:
   * const char *Moho::CLobbyTypeInfo::GetName();
   */
  const char* CLobbyTypeInfo::GetName() const
  {
    return "CLobby";
  }

  /**
   * Address: 0x007C0880 (FUN_007C0880, Moho::CLobbyTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::CLobbyTypeInfo::Init(gpg::RType *this);
   */
  void CLobbyTypeInfo::Init()
  {
    size_ = sizeof(CLobby);
    AddBase<CLobby, CScriptObject>();
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
