#include "moho/net/INetNATTraversalProviderTypeInfo.h"

#include "moho/net/INetNATTraversalProvider.h"

namespace moho
{
  /**
   * Address: 0x00481950 (FUN_00481950, Moho::INetNATTraversalProviderTypeInfo::dtr)
   */
  INetNATTraversalProviderTypeInfo::~INetNATTraversalProviderTypeInfo() = default;

  /**
   * Address: 0x00481940 (FUN_00481940, Moho::INetNATTraversalProviderTypeInfo::GetName)
   *
   * IDA signature:
   * const char *sub_481940();
   */
  const char* INetNATTraversalProviderTypeInfo::GetName() const
  {
    return "INetNATTraversalProvider";
  }

  /**
   * Address: 0x00481920 (FUN_00481920, Moho::INetNATTraversalProviderTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall sub_481920(_DWORD *this);
   */
  void INetNATTraversalProviderTypeInfo::Init()
  {
    size_ = sizeof(INetNATTraversalProvider);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
